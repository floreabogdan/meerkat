package suricata

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// defaultUpdateTimeout bounds a suricata-update run. It downloads the ruleset,
// merges it, applies the filters and then loads the result into a throwaway
// Suricata to check it parses — on a router that last step is the slow one, and
// 52,000 rules is not quick. Twenty minutes is far longer than it has ever
// taken and short enough that a hung run is not forever.
const defaultUpdateTimeout = 20 * time.Minute

// Updater runs suricata-update.
type Updater struct {
	// Bin is the suricata-update executable. Empty means look it up on PATH.
	Bin string
	// SuricataConf and DataDir are passed through so the updater reads the same
	// configuration the running sensor does rather than its own defaults.
	SuricataConf string
	DataDir      string
	// DisableConf and EnableConf are the filter files meerkat generated.
	DisableConf string
	EnableConf  string
	Timeout     time.Duration
}

// Output is what a run produced, in a form fit to store and to show.
type Output struct {
	Command  string
	ExitCode int
	Duration time.Duration
	// Log is the combined stdout and stderr, trimmed. suricata-update writes
	// everything worth reading to stderr, including the counts.
	Log string
}

// ErrUpdaterMissing means suricata-update is not installed. It is a distinct
// error because the answer is "apt install suricata-update", not "check the
// configuration".
var ErrUpdaterMissing = errors.New("suricata-update is not installed")

// Path resolves the updater executable.
func (u *Updater) Path() (string, error) {
	if u.Bin != "" {
		if _, err := os.Stat(u.Bin); err != nil {
			return "", fmt.Errorf("%w at %s", ErrUpdaterMissing, u.Bin)
		}
		return u.Bin, nil
	}
	p, err := exec.LookPath("suricata-update")
	if err != nil {
		return "", ErrUpdaterMissing
	}
	return p, nil
}

// Run fetches and rebuilds the ruleset.
//
// force makes suricata-update rebuild even when the sources have not changed,
// which is what applying a policy change needs: the merged rules file is the
// only place the filters take effect, and without -f a run that finds no new
// upstream rules would leave the old file in place and the change would
// silently not happen.
//
// Reload is deliberately left to the caller (--no-reload). suricata-update's
// own reload swallows the outcome; meerkat asks Suricata itself and reports
// what it said.
func (u *Updater) Run(ctx context.Context, force bool) (Output, error) {
	bin, err := u.Path()
	if err != nil {
		return Output{}, err
	}

	args := []string{"--no-reload"}
	if u.SuricataConf != "" {
		args = append(args, "--suricata-conf", u.SuricataConf)
	}
	if u.DataDir != "" {
		args = append(args, "--data-dir", u.DataDir)
	}
	if u.DisableConf != "" {
		args = append(args, "--disable-conf", u.DisableConf)
	}
	if u.EnableConf != "" {
		args = append(args, "--enable-conf", u.EnableConf)
	}
	if force {
		args = append(args, "-f")
	}

	timeout := u.Timeout
	if timeout <= 0 {
		timeout = defaultUpdateTimeout
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, bin, args...)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	// Keep the child's environment minimal and predictable. suricata-update is
	// Python and will otherwise inherit whatever PYTHONPATH the caller had.
	cmd.Env = append(os.Environ(), "PYTHONUNBUFFERED=1")

	start := time.Now()
	err = cmd.Run()
	out := Output{
		Command:  filepath.Base(bin) + " " + strings.Join(args, " "),
		Duration: time.Since(start).Round(time.Second),
		Log:      trimLog(buf.String()),
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			out.ExitCode = ee.ExitCode()
			return out, fmt.Errorf("suricata-update exited %d: %s", out.ExitCode, lastLine(out.Log))
		}
		if runCtx.Err() != nil {
			return out, fmt.Errorf("suricata-update timed out after %s", timeout)
		}
		return out, fmt.Errorf("suricata: run updater: %w", err)
	}
	return out, nil
}

// maxLogBytes bounds what is kept from a run. The interesting part of a
// suricata-update log is the last few lines; a rules file that fails to parse
// can produce megabytes of complaints, and that belongs in the journal, not in
// meerkat's database.
const maxLogBytes = 16 << 10

func trimLog(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxLogBytes {
		return s
	}
	return "… (truncated) …\n" + s[len(s)-maxLogBytes:]
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		s = s[i+1:]
	}
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	if s == "" {
		return "no output"
	}
	return s
}
