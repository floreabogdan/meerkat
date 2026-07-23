package store

import (
	"path/filepath"
	"testing"
	"time"
)

func rulesStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.SaveIdentity("edge1", "127.0.0.1:8100"); err != nil {
		t.Fatal(err)
	}
	return st
}

func indexRules(t *testing.T, st *Store, rules ...Rule) RuleIndexStats {
	t.Helper()
	ix, err := st.BeginRuleIndex()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if err := ix.Add(r); err != nil {
			t.Fatal(err)
		}
	}
	stats, err := ix.Commit()
	if err != nil {
		t.Fatal(err)
	}
	return stats
}

func rule(sid int, category, msg string, enabled bool) Rule {
	return Rule{SID: sid, GID: 1, Rev: 1, Action: "alert", Proto: "tcp",
		Msg: msg, Category: category, Enabled: enabled}
}

// An index pass replaces the catalogue wholesale, and has to report honestly
// what changed — a ruleset update that quietly dropped 400 rules is exactly the
// thing an operator wants to see in the history.
func TestRuleIndexReportsWhatChanged(t *testing.T) {
	st := rulesStore(t)

	first := indexRules(t, st,
		rule(1001, "ET SCAN", "ET SCAN one", true),
		rule(1002, "ET SCAN", "ET SCAN two", true),
		rule(1003, "GPL ICMP", "GPL ICMP ping", false),
	)
	if first.Total != 3 || first.Enabled != 2 || first.Added != 3 || first.Removed != 0 {
		t.Fatalf("first pass = %+v, want 3 total / 2 enabled / 3 added", first)
	}

	// 1003 is gone upstream, 1004 is new, 1001 has been disabled.
	second := indexRules(t, st,
		rule(1001, "ET SCAN", "ET SCAN one", false),
		rule(1002, "ET SCAN", "ET SCAN two", true),
		rule(1004, "ET MALWARE", "ET MALWARE new thing", true),
	)
	if second.Total != 3 || second.Enabled != 2 {
		t.Errorf("second pass totals = %+v", second)
	}
	if second.Added != 1 {
		t.Errorf("added = %d, want 1", second.Added)
	}
	if second.Removed != 1 {
		t.Errorf("removed = %d, want 1 (the rule that vanished upstream)", second.Removed)
	}

	counts, err := st.RuleCounts()
	if err != nil {
		t.Fatal(err)
	}
	if counts.Total != 3 || counts.Enabled != 2 {
		t.Errorf("counts = %+v", counts)
	}
	if _, err := st.GetRule(1003); err != ErrNotFound {
		t.Error("a rule removed upstream is still in the catalogue")
	}
}

// The reason policy lives in its own table: a decision must outlive the
// catalogue being rebuilt under it. ET Open retires and reinstates rules, and a
// rule someone muted must come back muted.
func TestPolicySurvivesARulesetRebuild(t *testing.T) {
	st := rulesStore(t)
	indexRules(t, st, rule(2403300, "ET CINS", "ET CINS group 1", true))

	if err := st.SetRulePolicy(RulePolicy{
		Scope: RuleScopeSID, Key: "2403300", State: RuleStateDisabled,
		Note: "pure noise", Actor: "admin",
	}); err != nil {
		t.Fatal(err)
	}

	// The rule disappears from upstream entirely...
	indexRules(t, st, rule(1001, "ET SCAN", "something else", true))
	// ...and comes back six months later.
	indexRules(t, st,
		rule(1001, "ET SCAN", "something else", true),
		rule(2403300, "ET CINS", "ET CINS group 1", true),
	)

	p, err := st.GetRulePolicy(RuleScopeSID, "2403300")
	if err != nil {
		t.Fatal(err)
	}
	if p.State != RuleStateDisabled || p.Note != "pure noise" {
		t.Errorf("policy after two rebuilds = %+v, want the decision intact", p)
	}
}

// A policy row that says nothing is not a policy. Storing empty rows would make
// "how many rules have I overridden" a lie, and would leave dead comments in
// the generated filter files.
func TestClearingEveryFieldRemovesThePolicy(t *testing.T) {
	st := rulesStore(t)
	if err := st.SetRulePolicy(RulePolicy{Scope: RuleScopeSID, Key: "5", State: RuleStateDisabled}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetRulePolicy(RulePolicy{Scope: RuleScopeSID, Key: "5"}); err != nil {
		t.Fatal(err)
	}
	all, err := st.RulePolicies()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 0 {
		t.Errorf("policies = %+v, want none left", all)
	}
}

func TestSetRulePolicyRejectsNonsense(t *testing.T) {
	st := rulesStore(t)
	for _, p := range []RulePolicy{
		{Scope: "everything", Key: "x", State: RuleStateDisabled},
		{Scope: RuleScopeSID, Key: "5", State: "deleted"},
		{Scope: RuleScopeSID, Key: "", State: RuleStateDisabled},
		{Scope: RuleScopeSID, Key: "5", Severity: 9},
	} {
		if err := st.SetRulePolicy(p); err == nil {
			t.Errorf("SetRulePolicy(%+v) was accepted", p)
		}
	}
}

// Reactions is what the ingest hot path consults. A category-scoped decision
// has to reach every rule in the category, and a per-rule decision has to be
// able to carve one back out — "mute all of ET CINS except this one" is the
// case the whole precedence exists for.
func TestReactionsExpandCategoriesAndLetASidWin(t *testing.T) {
	st := rulesStore(t)
	indexRules(t, st,
		rule(2403300, "ET CINS", "ET CINS group 1", true),
		rule(2403301, "ET CINS", "ET CINS group 2", true),
		rule(2010371, "ET SCAN", "ET SCAN Amap", true),
	)

	if err := st.SetRulePolicy(RulePolicy{
		Scope: RuleScopeCategory, Key: "ET CINS", AutoBlock: true, AutoBlockTTL: 3600, Severity: 4,
	}); err != nil {
		t.Fatal(err)
	}
	// One rule in the category is exempted from blocking.
	if err := st.SetRulePolicy(RulePolicy{
		Scope: RuleScopeSID, Key: "2403301", AutoBlock: false, Severity: 2,
	}); err != nil {
		t.Fatal(err)
	}

	rx, err := st.Reactions()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := rx.AutoBlock[2403300]; !ok {
		t.Error("the category decision did not reach 2403300")
	}
	if _, ok := rx.AutoBlock[2403301]; ok {
		t.Error("the per-rule exemption did not beat its category")
	}
	if _, ok := rx.AutoBlock[2010371]; ok {
		t.Error("a rule outside the category was caught by it")
	}
	if rx.AutoBlock[2403300].AutoBlockTTL != 3600 {
		t.Errorf("ttl = %d, want the category's 3600", rx.AutoBlock[2403300].AutoBlockTTL)
	}
	if rx.Severity[2403300] != 4 {
		t.Errorf("severity for 2403300 = %d, want 4 from the category", rx.Severity[2403300])
	}
	if rx.Severity[2403301] != 2 {
		t.Errorf("severity for 2403301 = %d, want the rule's own 2", rx.Severity[2403301])
	}
}

// A category auto-block on a meerkat that has never indexed a ruleset must
// cover nothing rather than everything. Failing towards "block less" is the
// only safe direction for a feature that changes the firewall unattended.
func TestCategoryAutoBlockCoversNothingWithoutACatalogue(t *testing.T) {
	st := rulesStore(t)
	if err := st.SetRulePolicy(RulePolicy{
		Scope: RuleScopeCategory, Key: "ET CINS", AutoBlock: true,
	}); err != nil {
		t.Fatal(err)
	}
	rx, err := st.Reactions()
	if err != nil {
		t.Fatal(err)
	}
	if len(rx.AutoBlock) != 0 {
		t.Errorf("auto-block covers %d rules with no catalogue indexed", len(rx.AutoBlock))
	}
}

// The catalogue's whole value is the join to what has actually fired. Without
// it the operator is picking among 52,000 rules blind.
func TestListRulesJoinsObservedVolumeAndSortsByIt(t *testing.T) {
	st := rulesStore(t)
	indexRules(t, st,
		rule(2403300, "ET CINS", "ET CINS group 1", true),
		rule(2010371, "ET SCAN", "ET SCAN Amap", true),
		rule(2100387, "GPL ICMP", "GPL ICMP mask reply", false),
	)

	ts := time.Now().UTC()
	batch := make([]Alert, 0, 12)
	for range 10 {
		batch = append(batch, Alert{Ts: ts, SrcIP: "203.0.113.5", SID: 2403300,
			Sig: "ET CINS group 1", RuleCategory: "ET CINS", Severity: 2})
	}
	batch = append(batch, Alert{Ts: ts, SrcIP: "203.0.113.6", SID: 2010371,
		Sig: "ET SCAN Amap", RuleCategory: "ET SCAN", Severity: 3})
	if err := st.RecordAlerts(batch); err != nil {
		t.Fatal(err)
	}

	list, total, err := st.ListRules(RuleFilter{Desc: true, PerPage: 10})
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 {
		t.Fatalf("total = %d, want 3", total)
	}
	if list[0].SID != 2403300 || list[0].Hits != 10 {
		t.Errorf("loudest rule = sid %d with %d hits, want 2403300 with 10", list[0].SID, list[0].Hits)
	}
	if list[1].SID != 2010371 || list[1].Hits != 1 {
		t.Errorf("second = sid %d with %d hits", list[1].SID, list[1].Hits)
	}
	if list[2].Hits != 0 {
		t.Errorf("a rule that never fired reports %d hits", list[2].Hits)
	}

	firing, total, err := st.ListRules(RuleFilter{Firing: true, PerPage: 10})
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(firing) != 2 {
		t.Errorf("firing-only returned %d of %d, want 2", len(firing), total)
	}

	cats, err := st.RuleCategories()
	if err != nil {
		t.Fatal(err)
	}
	if len(cats) != 3 {
		t.Fatalf("categories = %d, want 3", len(cats))
	}
	if cats[0].Name != "ET CINS" || cats[0].Hits != 10 {
		t.Errorf("noisiest category = %q with %d hits", cats[0].Name, cats[0].Hits)
	}
	if !cats[0].Partial() && cats[0].Total != cats[0].Enabled {
		t.Errorf("ET CINS enabled/total = %d/%d", cats[0].Enabled, cats[0].Total)
	}
}

// ET's category names are full of underscores — WEB_SPECIFIC_APPS, EXPLOIT_KIT
// — and an underscore is LIKE's single-character wildcard. Unescaped, a search
// for one category quietly matches others.
func TestRuleSearchEscapesLikeWildcards(t *testing.T) {
	st := rulesStore(t)
	indexRules(t, st,
		rule(1, "ET INFO", "ET USER_AGENTS Suspicious UA", true),
		rule(2, "ET INFO", "ET USERXAGENTS Not The Same Rule", true),
		rule(3, "ET INFO", "ET SCAN 100% definitely unrelated", true),
	)

	list, total, err := st.ListRules(RuleFilter{Query: "USER_AGENTS", PerPage: 10})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || list[0].SID != 1 {
		t.Errorf("searching USER_AGENTS matched %d rules, want only sid 1", total)
	}

	// A bare % must be a literal, not "match everything".
	if _, total, err := st.ListRules(RuleFilter{Query: "%", PerPage: 10}); err != nil {
		t.Fatal(err)
	} else if total != 1 {
		t.Errorf("searching for %% matched %d rules, want the 1 containing a literal %%", total)
	}
}

// An exact sid is the other way people search: they have a number from a log
// line and want the rule behind it.
func TestRuleSearchAcceptsASid(t *testing.T) {
	st := rulesStore(t)
	indexRules(t, st, rule(2010371, "ET SCAN", "ET SCAN Amap", true))
	list, total, err := st.ListRules(RuleFilter{Query: "2010371", PerPage: 10})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || list[0].SID != 2010371 {
		t.Errorf("searching by sid returned %d rules", total)
	}
}

// The classtype description Suricata puts in eve.json cannot tell a reputation
// hit from an intrusion — both are "Misc Attack". The message-prefix category
// is the axis rule management works on, so signatures stored before meerkat
// kept one have to be filled in rather than left blank forever.
func TestBackfillRuleCategories(t *testing.T) {
	st := rulesStore(t)
	ts := time.Now().UTC()
	if err := st.RecordAlerts([]Alert{
		{Ts: ts, SrcIP: "203.0.113.5", SID: 2403300, Sig: "ET CINS group 1", Category: "Misc Attack"},
		{Ts: ts, SrcIP: "203.0.113.6", SID: 2100387, Sig: "GPL ICMP mask reply", Category: "Misc activity"},
	}); err != nil {
		t.Fatal(err)
	}

	categoryOf := func(sig string) string {
		if len(sig) > 6 && sig[:6] == "ET CIN" {
			return "ET CINS"
		}
		return "GPL ICMP"
	}
	n, err := st.BackfillRuleCategories(categoryOf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("backfilled %d signatures, want 2", n)
	}
	// Running it twice must not rewrite rows it already filled.
	if n, err := st.BackfillRuleCategories(categoryOf); err != nil || n != 0 {
		t.Errorf("second backfill touched %d rows (err %v), want 0", n, err)
	}

	cats, err := st.ObservedCategories(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(cats) != 2 {
		t.Fatalf("observed categories = %+v", cats)
	}
}

// A failed apply is exactly as worth recording as a successful one: a rule
// change that did not reach the sensor is the thing somebody has to find later.
func TestRuleRunsKeepFailures(t *testing.T) {
	st := rulesStore(t)
	start := time.Now().UTC().Add(-time.Minute)
	if _, err := st.RecordRuleRun(RuleRun{
		StartedAt: start, FinishedAt: time.Now().UTC(), Kind: RuleRunApply,
		Actor: "admin", OK: false, Step: "running suricata-update",
		Error: "suricata-update exited 1: could not fetch the ruleset",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RecordRuleRun(RuleRun{
		StartedAt: start, FinishedAt: time.Now().UTC(), Kind: RuleRunApply,
		Actor: "admin", OK: true, Step: "done", RulesTotal: 52048, RulesEnabled: 51749,
		Reloaded: true,
	}); err != nil {
		t.Fatal(err)
	}

	runs, err := st.RuleRuns(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 2 {
		t.Fatalf("runs = %d, want 2 including the failure", len(runs))
	}
	if !runs[0].OK || runs[0].RulesTotal != 52048 {
		t.Errorf("newest run = %+v", runs[0])
	}
	if runs[1].OK || runs[1].Error == "" {
		t.Error("the failed run lost its error")
	}

	last, ok, err := st.LastRuleRun(RuleRunApply)
	if err != nil || !ok {
		t.Fatalf("LastRuleRun: ok=%v err=%v", ok, err)
	}
	if !last.OK {
		t.Error("LastRuleRun returned the older run")
	}
	if last.Duration() <= 0 {
		t.Error("duration is not derived from the timestamps")
	}
}

func TestSaveSuricataSettingsRoundTrip(t *testing.T) {
	st := rulesStore(t)
	settings, _, err := st.GetSettings()
	if err != nil {
		t.Fatal(err)
	}
	// The defaults are Debian's layout, which is what the routers run.
	if settings.SuricataRulesPath != "/var/lib/suricata/rules/suricata.rules" {
		t.Errorf("default rules path = %q", settings.SuricataRulesPath)
	}
	if settings.AutoBlockEnabled {
		t.Error("blocking on sight defaults to on; it must default to off")
	}
	if settings.RulesAutoUpdate {
		t.Error("automatic ruleset updates default to on; they must default to off")
	}

	settings.SuricataSocket = "/run/suricata/cmd.sock"
	settings.RulesAutoUpdate = true
	settings.RulesUpdateHour = 3
	settings.AutoBlockEnabled = true
	settings.AutoBlockMaxHour = 5
	if err := st.SaveSuricata(settings); err != nil {
		t.Fatal(err)
	}
	got, _, err := st.GetSettings()
	if err != nil {
		t.Fatal(err)
	}
	if got.SuricataSocket != "/run/suricata/cmd.sock" || !got.RulesAutoUpdate ||
		got.RulesUpdateHour != 3 || !got.AutoBlockEnabled || got.AutoBlockMaxHour != 5 {
		t.Errorf("round-tripped %+v", got)
	}

	settings.RulesUpdateHour = 25
	if err := st.SaveSuricata(settings); err == nil {
		t.Error("an out-of-range update hour was accepted")
	}
}

// Saving the settings must not tell the scheduler it already ran today — the
// same reason a settings save never touches the threat-map cursor.
func TestSavingSuricataSettingsDoesNotStampTheLastUpdate(t *testing.T) {
	st := rulesStore(t)
	when := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	if err := st.SetRulesLastUpdate(when); err != nil {
		t.Fatal(err)
	}
	settings, _, err := st.GetSettings()
	if err != nil {
		t.Fatal(err)
	}
	settings.RulesUpdateHour = 6
	if err := st.SaveSuricata(settings); err != nil {
		t.Fatal(err)
	}
	got, _, err := st.GetSettings()
	if err != nil {
		t.Fatal(err)
	}
	if !got.RulesLastUpdate.Equal(when) {
		t.Errorf("last update = %v, want it untouched at %v", got.RulesLastUpdate, when)
	}
}
