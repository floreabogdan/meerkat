package triage

import (
	"context"
	"testing"
	"time"

	"github.com/floreabogdan/meerkat/internal/store"
)

// autoSetup wires an auto-blocker over the shared test fixtures, with the
// master switch and the rule policy as given.
func autoSetup(t *testing.T, enabled bool, cap int, policies ...store.RulePolicy) (*Auto, *store.Store, *fakeNftably) {
	t.Helper()
	m, st, f := setup(t)
	if err := st.SaveIdentity("edge1", "127.0.0.1:8100"); err != nil {
		t.Fatal(err)
	}
	settings, _, err := st.GetSettings()
	if err != nil {
		t.Fatal(err)
	}
	settings.AutoBlockEnabled, settings.AutoBlockMaxHour = enabled, cap
	if err := st.SaveSuricata(settings); err != nil {
		t.Fatal(err)
	}
	for _, p := range policies {
		if err := st.SetRulePolicy(p); err != nil {
			t.Fatal(err)
		}
	}
	a := NewAuto(m, st, testLogger())
	a.refresh()
	return a, st, f
}

func alert(ip string, sid int, local bool) store.Alert {
	return store.Alert{
		Ts: time.Now().UTC(), SrcIP: ip, SID: sid, Sig: "ET SCAN Something",
		Severity: 2, IsLocal: local,
	}
}

// drain runs every queued candidate, so the test does not have to race a
// background goroutine.
func drain(a *Auto) {
	for {
		select {
		case c := <-a.queue:
			a.handle(context.Background(), c)
		default:
			return
		}
	}
}

// The master switch is the one thing standing between a mis-set rule and the
// firewall changing unattended. It defaults off, and a rule marked "block on
// sight" must do nothing at all until somebody turns it on.
func TestAutoBlockDoesNothingWhileTheMasterSwitchIsOff(t *testing.T) {
	a, st, f := autoSetup(t, false, 20, store.RulePolicy{
		Scope: store.RuleScopeSID, Key: "2001219", AutoBlock: true,
	})
	a.Consider([]store.Alert{alert("198.51.100.7", 2001219, false)})
	drain(a)

	if f.blocked["198.51.100.7"] {
		t.Error("a source was blocked with the master switch off")
	}
	src, _ := st.GetSource("198.51.100.7")
	if src.State != store.StateNew {
		t.Errorf("state = %q, want it untouched", src.State)
	}
}

func TestAutoBlockPushesToNftablyAndRecordsWhoDidIt(t *testing.T) {
	a, st, f := autoSetup(t, true, 20, store.RulePolicy{
		Scope: store.RuleScopeSID, Key: "2001219", AutoBlock: true,
		AutoBlockTTL: 3600, Note: "known scanner",
	})
	a.Consider([]store.Alert{alert("198.51.100.7", 2001219, false)})
	drain(a)

	if !f.blocked["198.51.100.7"] {
		t.Fatal("nftably was never asked to block it")
	}
	src, _ := st.GetSource("198.51.100.7")
	if src.State != store.StateBlocked {
		t.Errorf("state = %q, want blocked", src.State)
	}
	if src.BlockedUntil.IsZero() {
		t.Error("the auto-block TTL was not applied, so it would never lapse")
	}

	// The ledger has to make an unattended block explicable months later: who,
	// which rule, and why.
	actions, _ := st.ActionsForTarget("198.51.100.7", 10)
	if len(actions) != 1 {
		t.Fatalf("ledger = %+v, want one entry", actions)
	}
	if actions[0].Actor != "auto" {
		t.Errorf("actor = %q, want %q", actions[0].Actor, "auto")
	}
	if !contains(actions[0].Reason, "2001219") || !contains(actions[0].Reason, "known scanner") {
		t.Errorf("reason = %q, want the rule and the operator's note", actions[0].Reason)
	}
	if a.Stats().Blocked != 1 {
		t.Errorf("stats = %+v", a.Stats())
	}
}

// A private, loopback or CGNAT source is one of ours. Blocking it at the edge
// is a self-inflicted outage, and a rule that fires on internal traffic would
// otherwise do it repeatedly and unattended.
func TestAutoBlockNeverTouchesOurOwnAddresses(t *testing.T) {
	a, st, f := autoSetup(t, true, 20, store.RulePolicy{
		Scope: store.RuleScopeSID, Key: "2001219", AutoBlock: true,
	})
	a.Consider([]store.Alert{alert("192.168.1.50", 2001219, true)})
	drain(a)

	if len(f.blocked) != 0 {
		t.Errorf("nftably was asked to block %v", f.blocked)
	}
	src, _ := st.GetSource("192.168.1.50")
	if src.State != store.StateNew {
		t.Errorf("state = %q, want it untouched", src.State)
	}
	// It must not even reach the queue: a rule firing on internal traffic would
	// otherwise fill the ledger with one refusal per alert.
	if a.Stats().Considered != 0 {
		t.Errorf("considered = %d, want the local source filtered before the queue", a.Stats().Considered)
	}
}

// An allowlisted source is a decision somebody made deliberately. A rule set to
// block on sight must not quietly overrule it.
func TestAutoBlockRespectsAnAllowlistedSource(t *testing.T) {
	a, st, f := autoSetup(t, true, 20, store.RulePolicy{
		Scope: store.RuleScopeSID, Key: "2001219", AutoBlock: true,
	})
	if err := st.SetSourceState("198.51.100.7", store.StateAllowlisted, "our monitoring", "admin"); err != nil {
		t.Fatal(err)
	}
	a.Consider([]store.Alert{alert("198.51.100.7", 2001219, false)})
	drain(a)

	if f.blocked["198.51.100.7"] {
		t.Error("an allowlisted source was auto-blocked")
	}
	src, _ := st.GetSource("198.51.100.7")
	if src.State != store.StateAllowlisted {
		t.Errorf("state = %q, want it left allowlisted", src.State)
	}
}

// One rule firing 500 times from one address in one batch is one decision. Any
// other behaviour means 500 calls to nftably and 500 ledger entries.
func TestAutoBlockCollapsesARepeatingSource(t *testing.T) {
	a, _, _ := autoSetup(t, true, 20, store.RulePolicy{
		Scope: store.RuleScopeSID, Key: "2001219", AutoBlock: true,
	})
	batch := make([]store.Alert, 0, 500)
	for range 500 {
		batch = append(batch, alert("198.51.100.7", 2001219, false))
	}
	a.Consider(batch)

	if got := a.Stats().Considered; got != 1 {
		t.Errorf("considered = %d out of 500 identical alerts, want 1", got)
	}
	if len(a.queue) != 1 {
		t.Errorf("queued %d candidates, want 1", len(a.queue))
	}
}

// The rate limit is the safety net on a feature that acts without a person. One
// badly chosen rule must not be able to blackhole the internet before anybody
// notices.
func TestAutoBlockStopsAtTheHourlyLimit(t *testing.T) {
	a, _, f := autoSetup(t, true, 2, store.RulePolicy{
		Scope: store.RuleScopeSID, Key: "2001219", AutoBlock: true,
	})
	// Three distinct sources, a cap of two.
	for _, ip := range []string{"198.51.100.7", "203.0.113.49", "203.0.113.99"} {
		a.Consider([]store.Alert{alert(ip, 2001219, false)})
	}
	drain(a)

	if len(f.blocked) != 2 {
		t.Errorf("blocked %d addresses with a cap of 2: %v", len(f.blocked), f.blocked)
	}
	if a.Stats().RateLimited != 1 {
		t.Errorf("rate-limited = %d, want 1", a.Stats().RateLimited)
	}
}

// A cap of zero means the limiter is not configured. Failing towards "block
// nothing" is the only safe direction here.
func TestAutoBlockWithNoLimitConfiguredBlocksNothing(t *testing.T) {
	a, _, f := autoSetup(t, true, 0, store.RulePolicy{
		Scope: store.RuleScopeSID, Key: "2001219", AutoBlock: true,
	})
	a.Consider([]store.Alert{alert("198.51.100.7", 2001219, false)})
	drain(a)
	if len(f.blocked) != 0 {
		t.Errorf("blocked %v with no rate limit configured", f.blocked)
	}
}

// A rule with no auto-block policy is simply recorded, which is what almost
// every rule is.
func TestAutoBlockIgnoresRulesWithNoPolicy(t *testing.T) {
	a, _, f := autoSetup(t, true, 20)
	a.Consider([]store.Alert{alert("198.51.100.7", 2001219, false)})
	drain(a)
	if len(f.blocked) != 0 {
		t.Errorf("blocked %v with no rule marked", f.blocked)
	}
}

// A failed firewall call must leave the source in whatever state it was really
// in — the same promise a manual block makes — and must not be retried in a
// loop against a broken nftably.
func TestAutoBlockLeavesTheStateAloneWhenNftablyFails(t *testing.T) {
	a, st, f := autoSetup(t, true, 20, store.RulePolicy{
		Scope: store.RuleScopeSID, Key: "2001219", AutoBlock: true,
	})
	f.fail = true
	a.Consider([]store.Alert{alert("198.51.100.7", 2001219, false)})
	drain(a)

	src, _ := st.GetSource("198.51.100.7")
	if src.State == store.StateBlocked {
		t.Error("a source was marked blocked after nftably refused the call")
	}
	actions, _ := st.ActionsForTarget("198.51.100.7", 10)
	if len(actions) != 1 || actions[0].OK {
		t.Fatalf("ledger = %+v, want one failed entry", actions)
	}
	if a.Stats().Blocked != 0 {
		t.Errorf("counted %d blocks after a failure", a.Stats().Blocked)
	}
}

// The severity override is the other half of the rule policy, and ingest reads
// it per alert.
func TestSeverityOverrideIsServedToIngest(t *testing.T) {
	a, _, _ := autoSetup(t, false, 20, store.RulePolicy{
		Scope: store.RuleScopeSID, Key: "2001219", Severity: 4,
	})
	if got := a.SeverityFor(2001219); got != 4 {
		t.Errorf("SeverityFor(2001219) = %d, want 4", got)
	}
	if got := a.SeverityFor(9999); got != 0 {
		t.Errorf("SeverityFor(unknown) = %d, want 0 for no override", got)
	}
}

// Consider runs on the ingest write path. Alert storage applies backpressure
// because losing an alert is unacceptable, but stalling the reader on an HTTP
// call to nftably would turn a firewall hiccup into an ingest outage.
func TestConsiderNeverBlocksWhenTheQueueIsFull(t *testing.T) {
	a, _, _ := autoSetup(t, true, 20, store.RulePolicy{
		Scope: store.RuleScopeSID, Key: "2001219", AutoBlock: true,
	})
	// More distinct sources than the queue can hold, and nothing draining it.
	batch := make([]store.Alert, 0, autoQueueDepth+50)
	for i := range autoQueueDepth + 50 {
		batch = append(batch, alert(testIP(i), 2001219, false))
	}

	done := make(chan struct{})
	go func() {
		a.Consider(batch)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Consider blocked on a full queue — ingest would stall behind the firewall")
	}
	if a.Stats().Dropped == 0 {
		t.Error("a full queue dropped nothing and reported nothing")
	}
}

func testIP(i int) string {
	return "203.0." + itoa(i/256) + "." + itoa(i%256)
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
