package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/floreabogdan/meerkat/internal/rules"
	"github.com/floreabogdan/meerkat/internal/store"
	"github.com/floreabogdan/meerkat/internal/suricata"
)

// cmdRules is the ruleset side of meerkat from the command line.
//
// `apply` is the one that matters: it is the privileged half of rule
// management, run as root by the meerkat-apply systemd oneshot when the
// console leaves a request — or by hand on a source install, or by anyone who
// would rather not click. Everything it does is mechanical; every decision was
// already made and written into the staged filter files by the unprivileged
// console.
func cmdRules(args []string) error {
	if len(args) == 0 {
		rulesUsage()
		return fmt.Errorf("rules: a subcommand is required")
	}
	switch args[0] {
	case "apply":
		return cmdRulesApply(args[1:])
	case "index":
		return cmdRulesIndex(args[1:])
	case "status":
		return cmdRulesStatus(args[1:])
	case "-h", "--help", "help":
		rulesUsage()
		return nil
	default:
		rulesUsage()
		return fmt.Errorf("rules: unknown subcommand %q", args[0])
	}
}

func rulesUsage() {
	fmt.Fprint(os.Stderr, `meerkat rules — manage Suricata's ruleset

Usage:
  meerkat rules status     what is installed, and what is waiting to be applied
  meerkat rules index      re-read the built ruleset into meerkat's catalogue
  meerkat rules apply      install the staged filters, rebuild, and reload

"apply" needs root: it writes /etc/suricata, runs suricata-update, and talks to
Suricata's control socket. It is normally started by the meerkat-apply systemd
unit when the console asks for a change, so you should rarely need to run it.
`)
}

// rulesManager opens the store and builds a manager with the configured paths.
func rulesManager(dbPath string, log *slog.Logger) (*store.Store, *rules.Manager, error) {
	st, err := store.Open(dbPath)
	if err != nil {
		return nil, nil, fmt.Errorf("open database: %w", err)
	}
	settings, ok, err := st.GetSettings()
	if err != nil {
		st.Close()
		return nil, nil, err
	}
	if !ok {
		st.Close()
		return nil, nil, fmt.Errorf("meerkat has not been initialized — run \"meerkat init\" first")
	}
	return st, rules.New(rules.Config{
		Store: st,
		Paths: suricataPaths(settings, dbPath),
		Log:   log,
	}), nil
}

func cmdRulesApply(args []string) error {
	fs := flag.NewFlagSet("rules apply", flag.ExitOnError)
	dbPath := fs.String("db", defaultDBPath, "path to meerkat's SQLite database")
	force := fs.Bool("force", false, "rebuild even if the upstream ruleset has not changed")
	reason := fs.String("reason", "", "why (recorded in the run history)")
	wait := fs.Bool("wait", true, "wait for the run to finish (always true; kept for clarity in unit files)")
	fs.Parse(args)
	_ = *wait

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	st, mgr, err := rulesManager(*dbPath, log)
	if err != nil {
		return err
	}
	defer st.Close()

	// A request left by the console carries who asked and why. Running this by
	// hand with no pending request is also fine — it rebuilds from whatever is
	// staged, which is the policy as it currently stands.
	req, pending, err := suricata.ReadRequest(mgr.Paths())
	if err != nil {
		return err
	}
	if !pending {
		req = suricata.Request{
			RequestedAt: time.Now().UTC(),
			Actor:       "cli",
			Reason:      firstNonEmpty(*reason, "manual run of meerkat rules apply"),
			Force:       true,
		}
	}
	if *force {
		req.Force = true
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	res := mgr.ApplyLocally(ctx, req)

	// Write the result before clearing the request. The console watches for the
	// result file, and the systemd path unit re-fires on the request file
	// disappearing — doing these in the other order could start a second run
	// before the first one's outcome had been recorded.
	if err := suricata.WriteResult(mgr.Paths(), res); err != nil {
		return fmt.Errorf("write the result: %w", err)
	}
	if pending {
		if err := suricata.ClearRequest(mgr.Paths()); err != nil {
			return fmt.Errorf("clear the request: %w", err)
		}
	}

	fmt.Printf("%s in %s\n", res.Step, res.Duration)
	if res.OK {
		fmt.Printf("%d rules installed, %d enabled\n", res.Counts.Total, res.Counts.Enabled)
		fmt.Println(res.ReloadDetail)
		return nil
	}
	return fmt.Errorf("%s: %s", res.Step, res.Error)
}

func cmdRulesIndex(args []string) error {
	fs := flag.NewFlagSet("rules index", flag.ExitOnError)
	dbPath := fs.String("db", defaultDBPath, "path to meerkat's SQLite database")
	fs.Parse(args)

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	st, mgr, err := rulesManager(*dbPath, log)
	if err != nil {
		return err
	}
	defer st.Close()

	stats, err := mgr.Index()
	if err != nil {
		return err
	}
	fmt.Printf("%d rules indexed, %d enabled (%d new, %d gone)\n",
		stats.Total, stats.Enabled, stats.Added, stats.Removed)
	return nil
}

func cmdRulesStatus(args []string) error {
	fs := flag.NewFlagSet("rules status", flag.ExitOnError)
	dbPath := fs.String("db", defaultDBPath, "path to meerkat's SQLite database")
	fs.Parse(args)

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	st, mgr, err := rulesManager(*dbPath, log)
	if err != nil {
		return err
	}
	defer st.Close()

	s, err := mgr.Status()
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "ruleset\t%s\n", s.RulesFile)
	if !s.Readable {
		fmt.Fprintf(w, "readable\tno — %s\n", s.FileError)
	}
	fmt.Fprintf(w, "installed\t%d rules, %d enabled\n", s.Total, s.Enabled)
	if !s.IndexedAt.IsZero() {
		fmt.Fprintf(w, "indexed\t%s\n", s.IndexedAt.Local().Format("2006-01-02 15:04"))
	}
	fmt.Fprintf(w, "control socket\t%s\n", s.SensorDetail)
	fmt.Fprintf(w, "manageable\t%s\n", yesNo(s.Manageable, "yes", "no — "+s.Why))
	fmt.Fprintf(w, "policy\t%d decisions, %d rules block on sight\n", s.Policies, s.AutoRules)
	if s.Waiting+s.Refused+s.Unknown > 0 {
		fmt.Fprintf(w, "drift\t%d waiting, %d refused, %d unknown\n", s.Waiting, s.Refused, s.Unknown)
	}
	if s.Pending {
		fmt.Fprintf(w, "pending\tsince %s%s\n", s.PendingSince.Local().Format("15:04:05"),
			map[bool]string{true: " — nothing has picked it up; is meerkat-apply.path enabled?"}[s.Stale])
	}
	if s.HasRun {
		fmt.Fprintf(w, "last run\t%s %s, %s\n", s.LastRun.Kind,
			s.LastRun.FinishedAt.Local().Format("2006-01-02 15:04"),
			yesNo(s.LastRun.OK, "ok", "failed: "+s.LastRun.Error))
	}
	return w.Flush()
}

func yesNo(ok bool, yes, no string) string {
	if ok {
		return yes
	}
	return no
}

// suricataPaths resolves where the sensor's files live, from settings with the
// Debian defaults behind them. The staging directory always sits beside
// meerkat's database, so it belongs to meerkat whatever else is configured.
func suricataPaths(settings store.Settings, dbPath string) suricata.Paths {
	return suricata.Paths{
		Staging:   filepath.Join(dirOf(dbPath), "suricata"),
		ConfDir:   settings.SuricataConfDir,
		RulesFile: settings.SuricataRulesPath,
		DataDir:   settings.SuricataDataDir,
		Socket:    settings.SuricataSocket,
	}.Defaults()
}
