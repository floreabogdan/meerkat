// Package doctor implements meerkat's preflight checks (`meerkat doctor`): can
// it read eve.json, is Suricata actually running, are the geo databases present,
// is nftably reachable to block through, and is meerkat's own database writable.
// Every check is independent and best-effort — one failing check never prevents
// the others from running and reporting.
package doctor

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/floreabogdan/meerkat/internal/eve"
	"github.com/floreabogdan/meerkat/internal/geo"
	"github.com/floreabogdan/meerkat/internal/suricata"
)

type Status int

const (
	OK Status = iota
	Warn
	Fail
)

func (s Status) String() string {
	switch s {
	case OK:
		return "OK"
	case Warn:
		return "WARN"
	default:
		return "FAIL"
	}
}

type Result struct {
	Name   string
	Status Status
	Detail string
}

type Config struct {
	DBPath  string // meerkat's own SQLite file
	EvePath string // Suricata's eve.json

	// GeoIP database paths; empty ones are reported as absent, not as errors.
	ASNDB     string
	CountryDB string
	CityDB    string

	// NftablyURL is nftably's base URL (e.g. http://127.0.0.1:8099). Empty means
	// blocking is not configured yet.
	NftablyURL   string
	NftablyToken string

	// Threat-map publisher. ThreatsEnabled distinguishes "switched off" from
	// "misconfigured", which are very different answers.
	ThreatsEnabled bool
	ThreatsURL     string
	ThreatsToken   string
	SiteName       string
	SiteLat        float64
	SiteLng        float64
	HomeNets       []netip.Prefix

	// SuricataUnit is the systemd unit expected to be producing eve.json.
	SuricataUnit string

	// Rule management. RulesPath is the built ruleset meerkat reads,
	// SuricataSocket is how a rebuilt one reaches the running sensor, and
	// StagingDir is where the console leaves work for the privileged step.
	RulesPath      string
	SuricataSocket string
	StagingDir     string
}

// Run executes every check and returns all results, regardless of individual
// failures.
func Run(cfg Config) []Result {
	return []Result{
		checkEveReadable(cfg),
		checkEveFresh(cfg),
		checkSuricata(cfg),
		checkGeoIP(cfg),
		checkNftably(cfg),
		checkRuleset(cfg),
		checkRuleApply(cfg),
		checkThreatMap(cfg),
		checkDBDir(cfg),
	}
}

// Failed reports whether any result is a hard failure.
func Failed(results []Result) bool {
	for _, r := range results {
		if r.Status == Fail {
			return true
		}
	}
	return false
}

// checkEveReadable is the one that most often catches a real problem: eve.json
// is normally mode 0640 root:root, and meerkat runs as its own unprivileged
// account. Without a group grant the tailer just sits there logging permission
// denied forever, which looks exactly like "quiet network".
func checkEveReadable(cfg Config) Result {
	path := cfg.EvePath
	if path == "" {
		return Result{"eve.json readable", Fail, "no eve.json path configured"}
	}
	fi, err := os.Stat(path)
	if os.IsNotExist(err) {
		return Result{"eve.json readable", Warn, fmt.Sprintf(
			"%s does not exist yet — meerkat will wait for it. Expected if Suricata is stopped.", path)}
	}
	if err != nil {
		return Result{"eve.json readable", Fail, err.Error()}
	}
	f, err := os.Open(path)
	if err != nil {
		return Result{"eve.json readable", Fail, fmt.Sprintf(
			"%s exists but cannot be opened: %v — eve.json is usually mode 0640 root:root, so add meerkat to the group that owns it (e.g. adduser meerkat adm) or relax suricata.yaml's file mode",
			path, err)}
	}
	f.Close()
	return Result{"eve.json readable", OK, fmt.Sprintf("%s is readable (%s)", path, humanBytes(fi.Size()))}
}

// checkEveFresh reports how current the file is and whether its newest record
// actually parses. A stale eve.json is the failure mode with no error message:
// everything looks healthy and no alerts arrive.
func checkEveFresh(cfg Config) Result {
	fi, err := os.Stat(cfg.EvePath)
	if err != nil {
		return Result{"eve.json fresh", Warn, "skipped — eve.json is not present"}
	}
	if fi.Size() == 0 {
		return Result{"eve.json fresh", Warn, "eve.json is empty — Suricata has not written anything yet"}
	}
	age := time.Since(fi.ModTime())

	last, err := lastLine(cfg.EvePath)
	detail := fmt.Sprintf("last written %s ago", age.Round(time.Second))
	if err == nil && len(last) > 0 {
		if et := eve.TypeOf(last); et != "" {
			detail += fmt.Sprintf("; newest record is an %q event", et)
		} else {
			return Result{"eve.json fresh", Warn, detail + "; could not read event_type from the newest line — is this really eve.json (JSON lines)?"}
		}
	}
	if age > time.Hour {
		return Result{"eve.json fresh", Warn, detail + " — Suricata may be stopped or idle"}
	}
	return Result{"eve.json fresh", OK, detail}
}

// lastLine reads the final complete line of a file without loading all of it.
func lastLine(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	const tailBytes = 1 << 20
	start := max(fi.Size()-tailBytes, 0)
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	var last []byte
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			last = []byte(line)
		}
	}
	return last, sc.Err()
}

// checkSuricata asks systemd whether the sensor is running. Purely
// informational: meerkat is useful against a stopped Suricata (there is history
// to triage) — it just will not learn anything new.
func checkSuricata(cfg Config) Result {
	unit := cfg.SuricataUnit
	if unit == "" {
		unit = "suricata"
	}
	path, err := exec.LookPath("systemctl")
	if err != nil {
		return Result{"suricata service", Warn, "systemctl not found (not a systemd host?)"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, path, "is-active", unit).Output()
	state := strings.TrimSpace(string(out))
	switch state {
	case "active":
		return Result{"suricata service", OK, fmt.Sprintf("systemd unit %q is active", unit)}
	case "":
		return Result{"suricata service", Warn, fmt.Sprintf("systemd unit %q not found", unit)}
	default:
		return Result{"suricata service", Warn, fmt.Sprintf(
			"systemd unit %q is %s — meerkat will serve what it has already ingested but will not see anything new", unit, state)}
	}
}

// checkGeoIP opens whatever databases are actually present. Enrichment is an
// enhancement, never a prerequisite, so a miss here is always a warning.
//
// Absent and broken are reported differently on purpose. Most of these paths are
// a guess at a standard filename rather than something the operator typed, so
// "not there" is an ordinary state that should say what to do about it; "there
// but unreadable" is a fault and should say so.
func checkGeoIP(cfg Config) Result {
	asn, country, city := geo.PathIfExists(cfg.ASNDB), geo.PathIfExists(cfg.CountryDB), geo.PathIfExists(cfg.CityDB)
	if asn == "" && country == "" && city == "" {
		return Result{"geoip databases", Warn, "none found — sources will have no country or ASN. Turn on the monthly DB-IP Lite download under Settings → Enrichment, or drop .mmdb files where it points."}
	}
	// geo.Open always returns a usable enricher, even when some databases failed
	// to open — degrading is the whole contract — so close it either way.
	e, err := geo.Open(asn, country, city)
	defer e.Close() //nolint:staticcheck // e is never nil, error or not
	if err != nil {
		return Result{"geoip databases", Warn, "a database is present but could not be read: " + err.Error()}
	}

	var missing []string
	if asn == "" {
		missing = append(missing, "ASN (no autonomous system on any source)")
	}
	if country == "" {
		missing = append(missing, "country")
	}
	if city == "" {
		missing = append(missing, "city (so no coordinates — the threat map needs them)")
	}
	detail := e.Describes()
	if len(missing) > 0 {
		detail += " — not installed: " + strings.Join(missing, ", ")
	}

	// A database that opens but decodes to nothing is the silent failure worth
	// catching: the struct tags stop matching and every lookup returns zeroes.
	if g := e.Lookup("8.8.8.8"); g.Empty() {
		return Result{"geoip databases", Warn, detail + " — but a known address (8.8.8.8) enriched to nothing; the databases may not be the expected format"}
	}
	return Result{"geoip databases", OK, detail}
}

// checkNftably probes the block seam. Phase 2 pushes blocks through it; this
// check exists now so the token is minted and reachable before it is needed.
func checkNftably(cfg Config) Result {
	if cfg.NftablyURL == "" {
		return Result{"nftably reachable", Warn, "not configured — set nftably's URL and API token under Settings to enable blocking. Blocking goes through nftables, never through Suricata."}
	}
	if cfg.NftablyToken == "" {
		return Result{"nftably reachable", Warn, cfg.NftablyURL + " is set but no API token is — mint one in nftably under Settings → Automation API. Its /api/block returns 404, not 401, until a token exists."}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	url := strings.TrimRight(cfg.NftablyURL, "/") + "/api/blocked"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Result{"nftably reachable", Fail, err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+cfg.NftablyToken)

	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return Result{"nftably reachable", Fail, fmt.Sprintf("%s: %v", url, err)}
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var body struct {
			Blocked []struct{ IP, Note string } `json:"blocked"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body)
		return Result{"nftably reachable", OK, fmt.Sprintf("%s responded — %d address(es) currently blocked", cfg.NftablyURL, len(body.Blocked))}
	case http.StatusUnauthorized:
		return Result{"nftably reachable", Fail, "nftably rejected the API token (401) — check it against Settings → Automation API"}
	case http.StatusNotFound:
		return Result{"nftably reachable", Fail, "nftably returned 404 — its automation API is disabled until a token is minted under Settings → Automation API"}
	default:
		return Result{"nftably reachable", Fail, fmt.Sprintf("%s returned HTTP %d", url, resp.StatusCode)}
	}
}

// checkRuleset reports whether meerkat can read the ruleset Suricata is
// running. Everything the console says about a rule comes from this file, so if
// it cannot be read the Rules page is showing history, not fact.
func checkRuleset(cfg Config) Result {
	const name = "suricata ruleset"
	if cfg.RulesPath == "" {
		return Result{name, Warn, "no ruleset path configured"}
	}
	fi, err := os.Stat(cfg.RulesPath)
	if os.IsNotExist(err) {
		return Result{name, Warn, fmt.Sprintf(
			"%s does not exist — run suricata-update once, or point meerkat at the right path under Settings → Suricata",
			cfg.RulesPath)}
	}
	if err != nil {
		return Result{name, Fail, err.Error()}
	}
	f, err := os.Open(cfg.RulesPath)
	if err != nil {
		return Result{name, Fail, fmt.Sprintf(
			"%s exists but cannot be opened: %v — meerkat needs to read it to know which rules are installed",
			cfg.RulesPath, err)}
	}
	defer f.Close()

	// Parse it rather than only stat it. A ruleset meerkat cannot understand is
	// worth knowing about before the Rules page shows an empty catalogue and
	// nothing anywhere says why.
	counts, err := suricata.Scan(f, func(suricata.Rule) error { return nil })
	if err != nil {
		return Result{name, Fail, fmt.Sprintf("%s could not be parsed: %v", cfg.RulesPath, err)}
	}
	if counts.Total == 0 {
		return Result{name, Warn, fmt.Sprintf(
			"%s holds no rules meerkat could parse (%s)", cfg.RulesPath, humanBytes(fi.Size()))}
	}
	return Result{name, OK, fmt.Sprintf("%d rules installed, %d enabled (%s)",
		counts.Total, counts.Enabled, humanBytes(fi.Size()))}
}

// checkRuleApply reports whether a rule change can actually reach the sensor.
//
// This is the check worth having, because every part of it can be true
// separately and the failure is silent: the console accepts the change, writes
// its files, and nothing ever happens.
func checkRuleApply(cfg Config) Result {
	const name = "rule changes can be applied"

	updater := &suricata.Updater{}
	updaterPath, err := updater.Path()
	if err != nil {
		return Result{name, Warn,
			"suricata-update is not installed, so the ruleset cannot be rebuilt from meerkat — apt install suricata-update"}
	}

	if cfg.StagingDir != "" {
		if err := os.MkdirAll(cfg.StagingDir, 0o750); err != nil {
			return Result{name, Fail, fmt.Sprintf(
				"meerkat cannot create its staging directory %s: %v", cfg.StagingDir, err)}
		}
		probe := filepath.Join(cfg.StagingDir, ".doctor")
		if err := os.WriteFile(probe, []byte("ok\n"), 0o640); err != nil {
			return Result{name, Fail, fmt.Sprintf(
				"meerkat cannot write %s: %v — this is where it stages rule changes for the privileged step",
				cfg.StagingDir, err)}
		}
		os.Remove(probe)
	}

	// The path unit is what starts the privileged step. Without it the console
	// stages a change and waits forever.
	unit := "/lib/systemd/system/meerkat-apply.path"
	if _, err := os.Stat(unit); err != nil {
		if _, err := os.Stat("/etc/systemd/system/meerkat-apply.path"); err != nil {
			return Result{name, Warn, fmt.Sprintf(
				"suricata-update is at %s, but meerkat-apply.path is not installed — the console can stage a rule change and nothing will pick it up. Install it from deploy/, or run \"sudo meerkat rules apply\" by hand after each change.",
				updaterPath)}
		}
	}

	detail := "suricata-update at " + updaterPath + ", meerkat-apply.path installed"
	if cfg.SuricataSocket != "" {
		ctl := suricata.NewControl(cfg.SuricataSocket, 0)
		if ctl.Available() {
			detail += "; the sensor's control socket is open, so a new ruleset loads without a restart"
		} else {
			detail += "; the control socket " + cfg.SuricataSocket +
				" is not there — a rebuilt ruleset will only take effect when Suricata next starts"
		}
	}
	return Result{name, OK, detail}
}

// checkThreatMap validates the publisher's configuration without publishing
// anything. The checks it makes are the ones whose absence would be silent: a
// site at (0,0) draws every arc into the Atlantic, and an empty exclusion list
// would put customer addresses on a public page.
func checkThreatMap(cfg Config) Result {
	if !cfg.ThreatsEnabled {
		return Result{"threat map", OK, "publishing is off"}
	}
	var missing []string
	if cfg.ThreatsURL == "" {
		missing = append(missing, "collector URL")
	}
	if cfg.ThreatsToken == "" {
		missing = append(missing, "ingest token")
	}
	if cfg.SiteName == "" {
		missing = append(missing, "site name")
	}
	if cfg.SiteLat == 0 && cfg.SiteLng == 0 {
		missing = append(missing, "site coordinates")
	}
	if len(missing) > 0 {
		return Result{"threat map", Fail, "publishing is on but incomplete — missing " + strings.Join(missing, ", ")}
	}
	if len(cfg.HomeNets) == 0 {
		return Result{"threat map", Fail, "publishing is on but no networks are marked as ours; every detection from inside our own ranges would be published"}
	}

	u, err := url.Parse(cfg.ThreatsURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return Result{"threat map", Fail, fmt.Sprintf("collector URL %q is not a usable http(s) URL", cfg.ThreatsURL)}
	}
	detail := fmt.Sprintf("publishing to %s as %q, withholding %d of our own networks",
		u.Host, cfg.SiteName, len(cfg.HomeNets))
	if u.Scheme != "https" {
		return Result{"threat map", Warn, detail + " — over plain HTTP, so the ingest token crosses the network in the clear"}
	}
	return Result{"threat map", OK, detail}
}

func checkDBDir(cfg Config) Result {
	dir := filepath.Dir(cfg.DBPath)
	if dir == "" || dir == "." {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return Result{"database path", Fail, fmt.Sprintf("cannot create %s: %v", dir, err)}
	}
	probe := filepath.Join(dir, ".meerkat-write-test")
	if err := os.WriteFile(probe, []byte("ok"), 0o640); err != nil {
		return Result{"database path", Fail, fmt.Sprintf("%s is not writable: %v", dir, err)}
	}
	os.Remove(probe)

	// A writable directory is not enough: run "meerkat init" as root and the
	// database file it creates belongs to root, while the service runs as
	// meerkat. meerkat can then read its state but not write it — so it starts,
	// serves a login page, and fails on the first login. Check the file itself.
	if _, err := os.Stat(cfg.DBPath); err == nil {
		f, err := os.OpenFile(cfg.DBPath, os.O_WRONLY, 0)
		if err != nil {
			return Result{"database path", Fail, fmt.Sprintf(
				"%s exists but is not writable by this user: %v — fix with: sudo chown -R meerkat:meerkat %s", cfg.DBPath, err, dir)}
		}
		f.Close()
	}
	return Result{"database path", OK, dir + " and the database file are writable"}
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}
