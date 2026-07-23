// Package rules is meerkat's ruleset manager: it keeps a catalogue of what
// Suricata is actually running, turns the operator's decisions into the filter
// files suricata-update consumes, gets them applied, and then reads the result
// back to check they took.
//
// It is to internal/suricata what internal/triage is to internal/nftably — the
// half that knows about the database and the policy, sitting on top of a half
// that only knows the mechanics.
//
// The shape to understand before reading the rest: meerkat's service account
// cannot write /etc/suricata, cannot run suricata-update and cannot open a
// root-owned control socket, and that is deliberate — it parses
// attacker-influenced input all day and holds no capabilities at all. So an
// apply is a handoff. The console renders the filter files into its own state
// directory and leaves a request; a root oneshot picks it up, does the four
// privileged steps, and writes back what happened. Nothing is assumed to have
// worked: the catalogue is re-read from the rebuilt ruleset afterwards, and
// what the operator asked for is compared against what the sensor now holds.
package rules

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	"github.com/floreabogdan/meerkat/internal/store"
	"github.com/floreabogdan/meerkat/internal/suricata"
)

const (
	// pollInterval is how often the console checks whether the privileged step
	// has finished. An apply takes minutes (it downloads a ruleset and loads it
	// into a test Suricata), so this only has to feel responsive at the end.
	pollInterval = 5 * time.Second

	// scheduleInterval is how often the auto-update schedule is examined. The
	// schedule has hour granularity, so anything finer is wasted wakeups.
	scheduleInterval = 10 * time.Minute

	// staleRequest is how long a request may sit unclaimed before the console
	// says so. The privileged step is started by a systemd path unit; if that
	// unit is not installed the request would otherwise wait forever with the
	// UI showing a spinner and no explanation.
	staleRequest = 15 * time.Minute

	// runHistory bounds the kept run log.
	runHistory = 200
)

// Config is what a Manager needs.
type Config struct {
	Store *store.Store
	Paths suricata.Paths
	Log   *slog.Logger
}

// Manager owns the catalogue and the policy over it.
type Manager struct {
	store *store.Store
	paths suricata.Paths
	log   *slog.Logger
}

func New(cfg Config) *Manager {
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	return &Manager{store: cfg.Store, paths: cfg.Paths.Defaults(), log: log}
}

// Paths reports where this manager is looking.
func (m *Manager) Paths() suricata.Paths { return m.paths }

// ── the catalogue ────────────────────────────────────────────────────────

// Index rebuilds the catalogue from the ruleset file on disk.
//
// This reads what Suricata is running, not what meerkat asked for. Everything
// the console claims about the ruleset comes from here, which is what makes
// "disabled" mean the rule is commented out in the file rather than that
// somebody once pressed a button.
func (m *Manager) Index() (store.RuleIndexStats, error) {
	ix, err := m.store.BeginRuleIndex()
	if err != nil {
		return store.RuleIndexStats{}, err
	}
	counts, err := suricata.ScanFile(m.paths.RulesFile, func(r suricata.Rule) error {
		return ix.Add(store.Rule{
			SID: r.SID, GID: r.GID, Rev: r.Rev,
			Action: r.Action, Proto: r.Proto, Msg: r.Msg,
			Category: r.Category, Classtype: r.Classtype, Priority: r.Priority,
			ETSeverity: r.Severity, RuleCreated: r.CreatedAt, RuleUpdated: r.UpdatedAt,
			Enabled: r.Enabled,
		})
	})
	if err != nil {
		ix.Rollback()
		return store.RuleIndexStats{}, err
	}
	stats, err := ix.Commit()
	if err != nil {
		return store.RuleIndexStats{}, err
	}
	m.log.Info("indexed the suricata ruleset",
		"total", stats.Total, "enabled", stats.Enabled,
		"added", stats.Added, "removed", stats.Removed, "skipped", counts.Skipped)
	return stats, nil
}

// IndexIfStale re-indexes when the ruleset file has changed since the last
// pass. Somebody running suricata-update from a shell is a normal thing to do,
// and the console should notice rather than show a stale catalogue.
func (m *Manager) IndexIfStale() (store.RuleIndexStats, bool, error) {
	info, err := suricata.Stat(m.paths.RulesFile)
	if err != nil {
		return store.RuleIndexStats{}, false, err
	}
	counts, err := m.store.RuleCounts()
	if err != nil {
		return store.RuleIndexStats{}, false, err
	}
	// Never indexed, or the file is newer than the last pass.
	//
	// The mtime is truncated to the precision meerkat stores timestamps at
	// before comparing. Filesystems keep finer resolution than the microseconds
	// in store.TimeFormat — 100ns on NTFS, a nanosecond on ext4 — so an
	// untruncated mtime is almost always a few hundred nanoseconds "after" the
	// index that read it, and the file would look changed on every single
	// check. That is a 45 MB re-parse and 52,000 upserts every ten minutes,
	// forever, on a router.
	if counts.Total > 0 && !info.ModTime.Truncate(time.Microsecond).After(counts.IndexedAt) {
		return store.RuleIndexStats{}, false, nil
	}
	stats, err := m.Index()
	return stats, err == nil, err
}

// ── adoption ─────────────────────────────────────────────────────────────

// Adopt imports filters that were already in /etc/suricata before meerkat
// arrived.
//
// This runs once, and it exists because the alternative is data loss with a
// straight face. From the moment meerkat generates disable.conf, that file is a
// rendering of its policy — so anything in the old one that was not carried
// across would be silently switched back on by the next apply. The reference
// install held
// one hand-disabled sid. Filters meerkat cannot represent are returned rather
// than dropped, so the operator hears about them.
func (m *Manager) Adopt(actor string) (adopted int, unsupported []string, err error) {
	existing, err := m.store.RulePolicies()
	if err != nil {
		return 0, nil, err
	}
	if len(existing) > 0 {
		return 0, nil, nil // already has a policy; nothing to take over
	}

	started := time.Now().UTC()
	for _, f := range []struct {
		path  string
		state string
	}{
		{m.paths.LiveDisable(), store.RuleStateDisabled},
		{m.paths.LiveEnable(), store.RuleStateEnabled},
	} {
		a, err := suricata.ParseFilterFile(f.path)
		if err != nil {
			return adopted, unsupported, fmt.Errorf("rules: read %s: %w", f.path, err)
		}
		unsupported = append(unsupported, a.Unsupported...)
		for _, filter := range a.Filters {
			note := filter.Note
			if note == "" {
				note = "adopted from " + f.path
			}
			if err := m.store.SetRulePolicy(store.RulePolicy{
				Scope: filter.Scope, Key: filter.Key, State: f.state,
				Note: note, Actor: actor,
			}); err != nil {
				return adopted, unsupported, err
			}
			adopted++
		}
	}
	if adopted == 0 && len(unsupported) == 0 {
		return 0, nil, nil
	}

	detail := fmt.Sprintf("adopted %d existing filter(s) from %s", adopted, m.paths.ConfDir)
	if len(unsupported) > 0 {
		detail += fmt.Sprintf("; %d line(s) could not be represented and will be lost on the next apply", len(unsupported))
	}
	_, _ = m.store.RecordRuleRun(store.RuleRun{
		StartedAt: started, FinishedAt: time.Now().UTC(),
		Kind: store.RuleRunAdopt, Actor: actor, OK: true,
		Step: "done", Detail: detail,
	})
	m.log.Info("adopted existing suricata rule filters", "count", adopted, "unsupported", len(unsupported))
	return adopted, unsupported, nil
}

// ── staging and applying ─────────────────────────────────────────────────

// Filters renders the current policy into the two files suricata-update reads.
func (m *Manager) Filters() (suricata.Filters, error) {
	policies, err := m.store.RulePolicies()
	if err != nil {
		return suricata.Filters{}, err
	}
	var f suricata.Filters
	for _, p := range policies {
		filter := suricata.Filter{Scope: p.Scope, Key: p.Key, Note: policyNote(p)}
		switch p.State {
		case store.RuleStateDisabled:
			f.Disable = append(f.Disable, filter)
		case store.RuleStateEnabled:
			f.Enable = append(f.Enable, filter)
		}
	}
	return f, nil
}

func policyNote(p store.RulePolicy) string {
	who := p.Actor
	if who == "" {
		who = "meerkat"
	}
	note := p.Note
	if note == "" {
		note = "no reason given"
	}
	return fmt.Sprintf("%s — %s, %s", note, who, p.UpdatedAt.Format("2006-01-02"))
}

// ErrApplyPending means an apply is already in flight. Two concurrent
// suricata-update runs against the same data directory would race on the same
// output file, so the second is refused rather than queued.
var ErrApplyPending = errors.New("a ruleset change is already being applied")

// Stage writes the filter files and asks for them to be applied.
//
// It does not apply anything itself — it cannot. What it can do is fail early
// and clearly if the handoff will not work, rather than leaving a request file
// nobody will ever read.
func (m *Manager) Stage(actor, reason string, force bool) error {
	if pending, _, err := m.Pending(); err != nil {
		return err
	} else if pending {
		return ErrApplyPending
	}

	if err := os.MkdirAll(m.paths.Staging, 0o750); err != nil {
		return fmt.Errorf("rules: create the staging directory %s: %w", m.paths.Staging, err)
	}
	f, err := m.Filters()
	if err != nil {
		return err
	}
	now := time.Now()
	if err := os.WriteFile(m.paths.StagedDisable(), f.DisableConf(now), 0o640); err != nil {
		return fmt.Errorf("rules: stage disable.conf: %w", err)
	}
	if err := os.WriteFile(m.paths.StagedEnable(), f.EnableConf(now), 0o640); err != nil {
		return fmt.Errorf("rules: stage enable.conf: %w", err)
	}
	// A stale result from the previous run would otherwise be collected as if
	// it were this one's.
	if err := suricata.ClearResult(m.paths); err != nil {
		return fmt.Errorf("rules: clear the previous result: %w", err)
	}
	return suricata.WriteRequest(m.paths, suricata.Request{
		RequestedAt: now.UTC(), Actor: actor, Reason: reason, Force: force,
	})
}

// Pending reports whether an apply is waiting or running, and since when.
func (m *Manager) Pending() (bool, time.Time, error) {
	req, ok, err := suricata.ReadRequest(m.paths)
	if err != nil || !ok {
		return false, time.Time{}, err
	}
	return true, req.RequestedAt, nil
}

// ApplyLocally performs the privileged half in this process. It is what
// `meerkat rules apply` runs as root — from the systemd oneshot, or by hand on
// a source install where there is no oneshot.
func (m *Manager) ApplyLocally(ctx context.Context, req suricata.Request) suricata.Result {
	m.log.Info("applying the ruleset", "actor", req.Actor, "reason", req.Reason, "force", req.Force)
	res := suricata.Apply(ctx, m.paths, req)
	if res.OK {
		m.log.Info("ruleset applied", "rules", res.Counts.Total, "enabled", res.Counts.Enabled,
			"reloaded", res.Reloaded, "took", res.Duration)
	} else {
		m.log.Error("applying the ruleset failed", "step", res.Step, "err", res.Error)
	}
	return res
}

// Collect reads the outcome of a finished apply, records it, and re-indexes the
// catalogue from the ruleset that actually resulted.
//
// The re-index is the honest part. suricata-update re-enables a disabled rule
// when another enabled rule needs its flowbits, so "I disabled 299 rules" and
// "299 rules are disabled" are genuinely different claims — and the console
// makes the second one, by reading the file back.
func (m *Manager) Collect() (bool, error) {
	res, ok, err := suricata.ReadResult(m.paths)
	if err != nil || !ok {
		return false, err
	}

	run := store.RuleRun{
		StartedAt: res.StartedAt, FinishedAt: res.FinishedAt,
		Kind: store.RuleRunApply, Actor: res.Actor, Reason: res.Reason,
		OK: res.OK, Step: res.Step, Error: res.Error,
		RulesTotal: res.Counts.Total, RulesEnabled: res.Counts.Enabled,
		Reloaded: res.Reloaded, Detail: res.ReloadDetail, Log: res.Log,
	}

	if res.OK {
		if stats, err := m.Index(); err != nil {
			m.log.Warn("could not re-index after an apply", "err", err)
		} else {
			run.RulesTotal, run.RulesEnabled = stats.Total, stats.Enabled
			run.Added, run.Removed = stats.Added, stats.Removed
		}
		if err := m.store.SetRulesLastUpdate(res.FinishedAt); err != nil {
			m.log.Warn("could not stamp the last ruleset update", "err", err)
		}
	}

	if _, err := m.store.RecordRuleRun(run); err != nil {
		return false, err
	}
	_ = m.store.PruneRuleRuns(runHistory)
	if err := suricata.ClearResult(m.paths); err != nil {
		return false, err
	}
	return true, nil
}

// ── drift ────────────────────────────────────────────────────────────────

// The states a policy entry can be in relative to the running ruleset.
const (
	// DriftSatisfied: the sensor holds what the operator asked for.
	DriftSatisfied = "satisfied"
	// DriftPending: asked for, not applied yet.
	DriftPending = "pending"
	// DriftRefused: applied, and the ruleset still disagrees. Nearly always
	// suricata-update keeping a rule alive because an enabled rule depends on
	// its flowbits.
	DriftRefused = "refused"
	// DriftUnknown: the policy names a rule that is not in the catalogue.
	DriftUnknown = "unknown"
)

// Drift is one decision measured against the ruleset that is actually running.
type Drift struct {
	Policy store.RulePolicy
	Status string
	// Detail explains a status that is not "satisfied", in words fit for the UI.
	Detail string
}

// Drifts compares every decision against the built ruleset.
//
// This is the same idea as reconciling blocks against nftably: what meerkat
// remembers asking for is not evidence, and the file on disk is.
func (m *Manager) Drifts() ([]Drift, error) {
	policies, err := m.store.RulePolicies()
	if err != nil {
		return nil, err
	}
	var sids []int
	for _, p := range policies {
		if p.Scope == store.RuleScopeSID && p.State != store.RuleStateDefault {
			if sid, err := strconv.Atoi(p.Key); err == nil {
				sids = append(sids, sid)
			}
		}
	}
	enabled, err := m.store.RuleEnabledBySID(sids)
	if err != nil {
		return nil, err
	}
	cats, err := m.store.RuleCategories()
	if err != nil {
		return nil, err
	}
	byCat := make(map[string]store.RuleCategory, len(cats))
	for _, c := range cats {
		byCat[c.Name] = c
	}

	lastApply, _, err := m.store.LastRuleRun(store.RuleRunApply)
	if err != nil {
		return nil, err
	}

	var out []Drift
	for _, p := range policies {
		if p.State == store.RuleStateDefault {
			continue // auto-block and severity are meerkat's own; nothing to apply
		}
		d := Drift{Policy: p, Status: DriftSatisfied}
		switch p.Scope {
		case store.RuleScopeSID:
			sid, err := strconv.Atoi(p.Key)
			if err != nil {
				continue
			}
			on, known := enabled[sid]
			switch {
			case !known:
				d.Status, d.Detail = DriftUnknown, "this rule is not in the installed ruleset"
			case on && p.State == store.RuleStateDisabled:
				d.Status = DriftPending
			case !on && p.State == store.RuleStateEnabled:
				d.Status = DriftPending
			}
		case store.RuleScopeCategory:
			c, known := byCat[p.Key]
			switch {
			case !known:
				d.Status, d.Detail = DriftUnknown, "no rules in the installed ruleset carry this category"
			case p.State == store.RuleStateDisabled && c.Enabled > 0:
				d.Status = DriftPending
				d.Detail = fmt.Sprintf("%d of %d rules are still enabled", c.Enabled, c.Total)
			case p.State == store.RuleStateEnabled && c.Enabled < c.Total:
				d.Status = DriftPending
				d.Detail = fmt.Sprintf("%d of %d rules are still disabled", c.Total-c.Enabled, c.Total)
			}
		}
		// A change made before the last successful apply that still has not
		// taken was not ignored on the way — the sensor declined it.
		if d.Status == DriftPending && lastApply.OK && p.UpdatedAt.Before(lastApply.FinishedAt) {
			d.Status = DriftRefused
			if d.Detail == "" {
				d.Detail = "the last apply did not change this"
			}
			d.Detail += " — suricata-update keeps a disabled rule alive when an enabled rule needs its flowbits"
		}
		out = append(out, d)
	}
	return out, nil
}

// ── background ───────────────────────────────────────────────────────────

// Run keeps the catalogue current until ctx is done: it collects the results of
// applies, notices a ruleset changed from outside meerkat, and honours the
// auto-update schedule.
func (m *Manager) Run(ctx context.Context) {
	// Index at startup so a fresh install has a catalogue without anyone asking.
	if _, _, err := m.IndexIfStale(); err != nil {
		m.log.Warn("could not index the suricata ruleset", "err", err, "path", m.paths.RulesFile)
	}

	poll := time.NewTicker(pollInterval)
	defer poll.Stop()
	schedule := time.NewTicker(scheduleInterval)
	defer schedule.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-poll.C:
			if _, err := m.Collect(); err != nil {
				m.log.Warn("could not record the result of a ruleset apply", "err", err)
			}
		case <-schedule.C:
			if _, _, err := m.IndexIfStale(); err != nil {
				m.log.Warn("could not re-index the suricata ruleset", "err", err)
			}
			if err := m.maybeScheduleUpdate(); err != nil {
				m.log.Warn("could not start the scheduled ruleset update", "err", err)
			}
		}
	}
}

// maybeScheduleUpdate stages a fetch when the configured hour has come round
// and today's has not run.
func (m *Manager) maybeScheduleUpdate() error {
	settings, ok, err := m.store.GetSettings()
	if err != nil || !ok || !settings.RulesAutoUpdate {
		return err
	}
	now := time.Now()
	due := time.Date(now.Year(), now.Month(), now.Day(), settings.RulesUpdateHour, 0, 0, 0, now.Location())
	if now.Before(due) {
		return nil
	}
	if !settings.RulesLastUpdate.IsZero() && !settings.RulesLastUpdate.Before(due.UTC()) {
		return nil // already ran for today's slot
	}
	err = m.Stage("meerkat", "scheduled ruleset update", false)
	if errors.Is(err, ErrApplyPending) {
		return nil
	}
	if err == nil {
		m.log.Info("scheduled ruleset update requested", "hour", settings.RulesUpdateHour)
	}
	return err
}
