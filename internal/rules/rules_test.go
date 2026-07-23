package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/floreabogdan/meerkat/internal/store"
	"github.com/floreabogdan/meerkat/internal/suricata"
)

// ruleset is a miniature stand-in for /var/lib/suricata/rules/suricata.rules:
// two live ET CINS rules, a live ET SCAN rule, and one commented-out GPL ICMP
// rule. suricata-update writes a disabled rule as a comment rather than
// removing it, which is what these tests depend on.
const ruleset = `alert ip any any -> $HOME_NET any (msg:"ET CINS Poor Reputation IP group 1"; classtype:misc-attack; sid:2403300; rev:1;)
alert ip any any -> $HOME_NET any (msg:"ET CINS Poor Reputation IP group 2"; classtype:misc-attack; sid:2403301; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"ET SCAN Amap TCP Service Scan"; classtype:attempted-recon; sid:2010371; rev:2;)
# alert icmp any any -> $HOME_NET any (msg:"GPL ICMP Address Mask Reply"; classtype:misc-activity; sid:2100387; rev:8;)
`

func newManager(t *testing.T) (*Manager, *store.Store, suricata.Paths) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "meerkat.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.SaveIdentity("edge1", "127.0.0.1:8100"); err != nil {
		t.Fatal(err)
	}

	paths := suricata.Paths{
		Staging:   filepath.Join(dir, "staging"),
		ConfDir:   filepath.Join(dir, "etc"),
		RulesFile: filepath.Join(dir, "suricata.rules"),
		Socket:    filepath.Join(dir, "no-such.socket"),
	}.Defaults()
	for _, d := range []string{paths.Staging, paths.ConfDir} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(paths.RulesFile, []byte(ruleset), 0o644); err != nil {
		t.Fatal(err)
	}
	return New(Config{Store: st, Paths: paths}), st, paths
}

func TestIndexReadsWhatTheSensorIsActuallyRunning(t *testing.T) {
	m, st, _ := newManager(t)
	stats, err := m.Index()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Total != 4 || stats.Enabled != 3 {
		t.Fatalf("indexed %+v, want 4 rules with 3 enabled", stats)
	}

	// The disabled rule has to be in the catalogue, not missing from it: it is
	// the one an operator can switch back on.
	off, err := st.GetRule(2100387)
	if err != nil {
		t.Fatal(err)
	}
	if off.Enabled {
		t.Error("the commented-out rule was indexed as enabled")
	}
	if off.Category != "GPL ICMP" {
		t.Errorf("category = %q", off.Category)
	}
}

func TestIndexIfStaleSkipsAnUnchangedFile(t *testing.T) {
	m, _, paths := newManager(t)
	if _, err := m.Index(); err != nil {
		t.Fatal(err)
	}
	if _, ran, err := m.IndexIfStale(); err != nil || ran {
		t.Fatalf("re-indexed an unchanged ruleset (ran=%v err=%v)", ran, err)
	}

	// Somebody runs suricata-update from a shell. The console must notice.
	later := time.Now().Add(time.Hour)
	if err := os.WriteFile(paths.RulesFile, []byte(ruleset+
		`alert tcp any any -> any any (msg:"ET SCAN Brand New"; sid:2010999; rev:1;)`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(paths.RulesFile, later, later); err != nil {
		t.Fatal(err)
	}
	stats, ran, err := m.IndexIfStale()
	if err != nil || !ran {
		t.Fatalf("did not re-index a changed ruleset (ran=%v err=%v)", ran, err)
	}
	if stats.Added != 1 {
		t.Errorf("added = %d, want the 1 new rule", stats.Added)
	}
}

// The moment meerkat writes disable.conf, that file is a rendering of its
// policy — so anything already in it that was not carried across gets silently
// switched back on. A typical install has a few hand-disabled sids already.
func TestAdoptTakesOverAnExistingDisableConf(t *testing.T) {
	m, st, paths := newManager(t)
	if err := os.WriteFile(paths.LiveDisable(), []byte(
		"# too noisy for us\n2100387\ngroup:emerging-icmp.rules\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	adopted, unsupported, err := m.Adopt("meerkat")
	if err != nil {
		t.Fatal(err)
	}
	if adopted != 1 {
		t.Fatalf("adopted %d filters, want the one sid", adopted)
	}
	if len(unsupported) != 1 || !strings.Contains(unsupported[0], "group:") {
		t.Errorf("unsupported = %q, want the group: line reported rather than dropped", unsupported)
	}

	p, err := st.GetRulePolicy(store.RuleScopeSID, "2100387")
	if err != nil {
		t.Fatal(err)
	}
	if p.State != store.RuleStateDisabled {
		t.Errorf("adopted policy = %+v, want disabled", p)
	}
	if p.Note != "too noisy for us" {
		t.Errorf("the comment above the filter was not kept: %q", p.Note)
	}

	// The rendered file must reproduce it, or the next apply undoes the
	// adoption it just did.
	f, err := m.Filters()
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Disable) != 1 || f.Disable[0].Key != "2100387" {
		t.Errorf("rendered filters = %+v", f.Disable)
	}

	// Adoption is once-only: running again must not re-import and must not
	// overwrite decisions made since.
	if n, _, err := m.Adopt("meerkat"); err != nil || n != 0 {
		t.Errorf("second adopt imported %d filters (err %v)", n, err)
	}
}

func TestAdoptDoesNothingWhenMeerkatAlreadyHasAPolicy(t *testing.T) {
	m, st, paths := newManager(t)
	if err := st.SetRulePolicy(store.RulePolicy{
		Scope: store.RuleScopeSID, Key: "2010371", State: store.RuleStateDisabled,
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.LiveDisable(), []byte("2100387\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if n, _, err := m.Adopt("meerkat"); err != nil || n != 0 {
		t.Errorf("adopt ran over an existing policy: %d filters (err %v)", n, err)
	}
}

// Drift is the ruleset equivalent of reconciling blocks against nftables: what
// meerkat asked for is not evidence, and the built ruleset is.
func TestDriftsMeasureIntentAgainstTheBuiltRuleset(t *testing.T) {
	m, st, _ := newManager(t)
	if _, err := m.Index(); err != nil {
		t.Fatal(err)
	}

	// Asked for and not applied.
	must(t, st.SetRulePolicy(store.RulePolicy{
		Scope: store.RuleScopeSID, Key: "2010371", State: store.RuleStateDisabled}))
	// Already true in the file: 2100387 is commented out.
	must(t, st.SetRulePolicy(store.RulePolicy{
		Scope: store.RuleScopeSID, Key: "2100387", State: store.RuleStateDisabled}))
	// Names a rule the sensor does not have.
	must(t, st.SetRulePolicy(store.RulePolicy{
		Scope: store.RuleScopeSID, Key: "9999999", State: store.RuleStateDisabled}))
	// A whole category, none of which is off yet.
	must(t, st.SetRulePolicy(store.RulePolicy{
		Scope: store.RuleScopeCategory, Key: "ET CINS", State: store.RuleStateDisabled}))

	byKey := driftsByKey(t, m)
	if got := byKey["2010371"].Status; got != DriftPending {
		t.Errorf("un-applied rule = %q, want %q", got, DriftPending)
	}
	if got := byKey["2100387"].Status; got != DriftSatisfied {
		t.Errorf("already-disabled rule = %q, want %q", got, DriftSatisfied)
	}
	if got := byKey["9999999"].Status; got != DriftUnknown {
		t.Errorf("rule not in the ruleset = %q, want %q", got, DriftUnknown)
	}
	cins := byKey["ET CINS"]
	if cins.Status != DriftPending {
		t.Errorf("category = %q, want %q", cins.Status, DriftPending)
	}
	if !strings.Contains(cins.Detail, "2 of 2") {
		t.Errorf("category detail = %q, want it to say how many are still on", cins.Detail)
	}

	// After an apply that succeeded, a decision that still has not taken was
	// not merely queued — the sensor declined it, and saying "waiting" forever
	// would be the lie.
	if _, err := st.RecordRuleRun(store.RuleRun{
		StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC().Add(time.Minute),
		Kind: store.RuleRunApply, OK: true, Step: "done",
	}); err != nil {
		t.Fatal(err)
	}
	byKey = driftsByKey(t, m)
	if got := byKey["2010371"].Status; got != DriftRefused {
		t.Errorf("after a successful apply the un-taken rule = %q, want %q", got, DriftRefused)
	}
	if !strings.Contains(byKey["2010371"].Detail, "flowbits") {
		t.Errorf("detail = %q, want it to explain why suricata-update keeps a rule alive", byKey["2010371"].Detail)
	}
	if got := byKey["2100387"].Status; got != DriftSatisfied {
		t.Errorf("a satisfied decision changed to %q after an apply", got)
	}
}

// Auto-block and severity are meerkat's own behaviour — nothing about them
// reaches Suricata — so they must never show up as a ruleset change waiting to
// be applied.
func TestDriftsIgnoreDecisionsThatNeverTouchTheSensor(t *testing.T) {
	m, st, _ := newManager(t)
	if _, err := m.Index(); err != nil {
		t.Fatal(err)
	}
	must(t, st.SetRulePolicy(store.RulePolicy{
		Scope: store.RuleScopeSID, Key: "2403300", AutoBlock: true, Severity: 1}))

	drifts, err := m.Drifts()
	if err != nil {
		t.Fatal(err)
	}
	if len(drifts) != 0 {
		t.Errorf("drifts = %+v, want none — nothing here changes the ruleset", drifts)
	}
}

func TestStageWritesTheFiltersAndOneRequest(t *testing.T) {
	m, st, paths := newManager(t)
	must(t, st.SetRulePolicy(store.RulePolicy{
		Scope: store.RuleScopeCategory, Key: "ET CINS", State: store.RuleStateDisabled,
		Note: "reputation noise", Actor: "admin"}))

	if err := m.Stage("admin", "muted the reputation feeds", true); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(paths.StagedDisable())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `re:msg:"ET CINS `) {
		t.Errorf("staged disable.conf does not contain the category matcher:\n%s", body)
	}
	if !strings.Contains(string(body), "reputation noise") {
		t.Errorf("the reason did not reach the file, so /etc/suricata cannot explain itself:\n%s", body)
	}
	// The live files are untouched: meerkat cannot write them, and Stage must
	// not pretend otherwise.
	if _, err := os.Stat(paths.LiveDisable()); !os.IsNotExist(err) {
		t.Error("Stage wrote into the suricata config directory itself")
	}

	req, ok, err := suricata.ReadRequest(paths)
	if err != nil || !ok {
		t.Fatalf("no request was left for the privileged step (ok=%v err=%v)", ok, err)
	}
	if req.Actor != "admin" || !req.Force {
		t.Errorf("request = %+v", req)
	}

	// Two suricata-update runs against the same data directory would race on
	// the same output file.
	if err := m.Stage("admin", "again", true); err != ErrApplyPending {
		t.Errorf("a second stage returned %v, want ErrApplyPending", err)
	}
}

// Collect is the honest half: it records what the privileged step reported and
// then re-reads the ruleset, so the console's numbers come from the file rather
// than from the request.
func TestCollectRecordsTheOutcomeAndReindexes(t *testing.T) {
	m, st, paths := newManager(t)

	if done, err := m.Collect(); err != nil || done {
		t.Fatalf("collected a result that does not exist (done=%v err=%v)", done, err)
	}

	start := time.Now().UTC().Add(-2 * time.Minute)
	must(t, suricata.WriteResult(paths, suricata.Result{
		StartedAt: start, FinishedAt: time.Now().UTC(),
		Actor: "admin", Reason: "muted ET CINS", OK: true, Step: suricata.StepDone,
		Reloaded: true, ReloadDetail: "done",
		// Deliberately wrong: the privileged step counted 999, and the
		// catalogue must come from the file, not from this number.
		Counts: suricata.Counts{Total: 999, Enabled: 999},
	}))

	done, err := m.Collect()
	if err != nil || !done {
		t.Fatalf("Collect: done=%v err=%v", done, err)
	}
	runs, err := st.RuleRuns(5)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(runs))
	}
	if runs[0].RulesTotal != 4 || runs[0].RulesEnabled != 3 {
		t.Errorf("recorded %d/%d rules, want the 4/3 actually in the file",
			runs[0].RulesTotal, runs[0].RulesEnabled)
	}
	if !runs[0].Reloaded || runs[0].Actor != "admin" {
		t.Errorf("run = %+v", runs[0])
	}

	// The result must be consumed, or every poll records it again.
	if done, err := m.Collect(); err != nil || done {
		t.Errorf("the result survived being collected (done=%v err=%v)", done, err)
	}

	settings, _, err := st.GetSettings()
	if err != nil {
		t.Fatal(err)
	}
	if settings.RulesLastUpdate.IsZero() {
		t.Error("a successful apply did not stamp the last-update time, so the scheduler would repeat it")
	}
}

func TestCollectRecordsAFailureWithoutReindexing(t *testing.T) {
	m, st, paths := newManager(t)
	must(t, suricata.WriteResult(paths, suricata.Result{
		StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC(),
		Actor: "admin", OK: false, Step: suricata.StepUpdate,
		Error: "suricata-update exited 1: could not fetch the ruleset",
	}))
	if done, err := m.Collect(); err != nil || !done {
		t.Fatalf("Collect: done=%v err=%v", done, err)
	}
	runs, err := st.RuleRuns(5)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0].OK {
		t.Fatalf("runs = %+v, want one failed run", runs)
	}
	if runs[0].Error == "" || runs[0].Step != suricata.StepUpdate {
		t.Errorf("the failure lost its detail: %+v", runs[0])
	}
	// A failed apply must not claim the ruleset was refreshed.
	settings, _, err := st.GetSettings()
	if err != nil {
		t.Fatal(err)
	}
	if !settings.RulesLastUpdate.IsZero() {
		t.Error("a failed apply stamped the last-update time")
	}
}

// Status is what the page is built from, and its job when things are broken is
// to say so rather than offer a button that silently does nothing.
func TestStatusExplainsWhyItCannotManage(t *testing.T) {
	m, _, paths := newManager(t)
	if err := os.Remove(paths.RulesFile); err != nil {
		t.Fatal(err)
	}
	s, err := m.Status()
	if err != nil {
		t.Fatal(err)
	}
	if s.Manageable {
		t.Error("reports it can manage a ruleset file that does not exist")
	}
	if !strings.Contains(s.Why, paths.RulesFile) {
		t.Errorf("Why = %q, want it to name the missing file", s.Why)
	}
	if s.SensorLive {
		t.Error("reports the sensor as running with no control socket")
	}
}

func driftsByKey(t *testing.T, m *Manager) map[string]Drift {
	t.Helper()
	drifts, err := m.Drifts()
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[string]Drift, len(drifts))
	for _, d := range drifts {
		out[d.Policy.Key] = d
	}
	return out
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
