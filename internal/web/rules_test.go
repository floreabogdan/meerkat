package web

import (
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/floreabogdan/meerkat/internal/rules"
	"github.com/floreabogdan/meerkat/internal/store"
	"github.com/floreabogdan/meerkat/internal/suricata"
)

const testRuleset = `alert ip any any -> $HOME_NET any (msg:"ET CINS Poor Reputation IP group 1"; classtype:misc-attack; sid:2403300; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"ET SCAN Amap TCP Service Scan"; classtype:attempted-recon; sid:2010371; rev:2;)
# alert icmp any any -> $HOME_NET any (msg:"GPL ICMP Address Mask Reply"; classtype:misc-activity; sid:2100387; rev:8;)
`

// rulesServer is testServer plus a live rule manager over a miniature ruleset.
func rulesServer(t *testing.T) (*Server, *store.Store, *rules.Manager) {
	t.Helper()
	srv, st := testServer(t)

	dir := t.TempDir()
	rulesFile := filepath.Join(dir, "suricata.rules")
	if err := os.WriteFile(rulesFile, []byte(testRuleset), 0o644); err != nil {
		t.Fatal(err)
	}
	paths := suricata.Paths{
		Staging:   filepath.Join(dir, "staging"),
		ConfDir:   filepath.Join(dir, "etc"),
		RulesFile: rulesFile,
		Socket:    filepath.Join(dir, "absent.socket"),
	}.Defaults()
	if err := os.MkdirAll(paths.ConfDir, 0o750); err != nil {
		t.Fatal(err)
	}

	mgr := rules.New(rules.Config{
		Store: st, Paths: paths,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if _, err := mgr.Index(); err != nil {
		t.Fatal(err)
	}
	srv.rules = mgr
	return srv, st, mgr
}

func TestRulesPagesRender(t *testing.T) {
	srv, _, _ := rulesServer(t)
	cookie := login(t, srv)

	for _, path := range []string{
		"/rules",
		"/rules?tab=catalogue",
		"/rules?tab=catalogue&q=ET+SCAN&state=enabled&policy=any&firing=1",
		"/rules?tab=changes",
		"/rules?tab=history",
		"/rules/2010371",
		"/settings?tab=suricata",
	} {
		rec := get(t, srv, cookie, path)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", path, rec.Code)
			continue
		}
		body := rec.Body.String()
		// The CSP sets style-src 'self' with no 'unsafe-inline', so an inline
		// style attribute is silently dropped in a real browser while passing
		// every server-side assertion. Guarded here as well as in the shared
		// test, because these pages are new.
		if i := strings.Index(body, `style="`); i >= 0 {
			t.Errorf("%s has an inline style the CSP will drop: %s", path, body[i:min(i+80, len(body))])
		}
	}

	body := get(t, srv, cookie, "/rules?tab=catalogue").Body.String()
	if !strings.Contains(body, "2403300") || !strings.Contains(body, "ET SCAN Amap") {
		t.Error("the catalogue does not list the indexed rules")
	}
	// The disabled rule must be visible: it is the one an operator can turn on.
	if !strings.Contains(body, "2100387") {
		t.Error("a rule disabled in the ruleset is missing from the catalogue")
	}
}

// A console with no sensor to manage must explain itself rather than 500 or
// offer buttons that cannot work.
func TestRulesPageWithoutAManagerExplainsItself(t *testing.T) {
	srv, _ := testServer(t)
	cookie := login(t, srv)

	rec := get(t, srv, cookie, "/rules")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /rules with no manager = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "not available") {
		t.Error("the page does not say rule management is unavailable")
	}
	if strings.Contains(body, `action="/rules/apply"`) {
		t.Error("an Apply button is offered on a console that cannot apply anything")
	}
	if rec := get(t, srv, cookie, "/rules/2010371"); rec.Code != http.StatusNotFound {
		t.Errorf("GET a rule with no manager = %d, want 404", rec.Code)
	}
}

func TestRulePolicyFormRecordsADecision(t *testing.T) {
	srv, st, _ := rulesServer(t)
	cookie := login(t, srv)

	rec := post(t, srv, cookie, "/rules/policy", url.Values{
		"scope": {"sid"}, "key": {"2403300"}, "state": {"disabled"},
		"note": {"pure reputation noise"}, "back": {"/rules?tab=catalogue"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("policy POST = %d, want 303", rec.Code)
	}
	p, err := st.GetRulePolicy(store.RuleScopeSID, "2403300")
	if err != nil {
		t.Fatal(err)
	}
	if p.State != store.RuleStateDisabled || p.Note != "pure reputation noise" {
		t.Errorf("stored policy = %+v", p)
	}
	if p.Actor != "admin" {
		t.Errorf("actor = %q, want the logged-in user", p.Actor)
	}

	// Deciding something about the ruleset is a change to what the network
	// reports, so it belongs in the ledger next to firewall changes.
	actions, err := st.ActionsForTarget("sid:2403300", 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 1 {
		t.Errorf("ledger entries = %d, want 1", len(actions))
	}
}

// Marking a rule "block on sight" while the master switch is off is a decision
// that would silently do nothing. It has to be recorded and said out loud.
func TestAutoBlockWithoutTheMasterSwitchWarnsRatherThanLying(t *testing.T) {
	srv, st, _ := rulesServer(t)
	cookie := login(t, srv)

	rec := post(t, srv, cookie, "/rules/policy", url.Values{
		"scope": {"sid"}, "key": {"2010371"}, "autoblock": {"1"}, "autoblock_ttl": {"24h"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("policy POST = %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "switched+off") {
		t.Errorf("redirect = %q, want it to say blocking on sight is off", loc)
	}

	p, err := st.GetRulePolicy(store.RuleScopeSID, "2010371")
	if err != nil {
		t.Fatal(err)
	}
	if !p.AutoBlock || p.AutoBlockTTL != 86400 {
		t.Errorf("policy = %+v, want the decision recorded with its TTL", p)
	}
}

func TestRulePolicyRejectsRubbish(t *testing.T) {
	srv, st, _ := rulesServer(t)
	cookie := login(t, srv)

	for _, form := range []url.Values{
		{"scope": {"the whole internet"}, "key": {"2403300"}, "state": {"disabled"}},
		{"scope": {"sid"}, "key": {"2403300"}, "state": {"deleted"}},
		{"scope": {"sid"}, "key": {""}, "state": {"disabled"}},
	} {
		rec := post(t, srv, cookie, "/rules/policy", form)
		if rec.Code != http.StatusSeeOther {
			t.Errorf("POST %v = %d, want a 303 with an error flash", form, rec.Code)
		}
		if !strings.Contains(rec.Header().Get("Location"), "err=") {
			t.Errorf("POST %v redirected without an error: %q", form, rec.Header().Get("Location"))
		}
	}
	if all, err := st.RulePolicies(); err != nil || len(all) != 0 {
		t.Errorf("policies = %+v (err %v), want none stored", all, err)
	}
}

// The back parameter comes from the page, but a crafted request could put
// anything in it.
func TestRulesFormsCannotBecomeAnOpenRedirect(t *testing.T) {
	srv, _, _ := rulesServer(t)
	cookie := login(t, srv)

	for _, back := range []string{
		"https://evil.example/",
		"//evil.example/",
		"http://evil.example/rules",
		"/\\evil.example",
	} {
		rec := post(t, srv, cookie, "/rules/policy", url.Values{
			"scope": {"sid"}, "key": {"2403300"}, "state": {"disabled"}, "back": {back},
		})
		loc := rec.Header().Get("Location")
		if !strings.HasPrefix(loc, "/rules") {
			t.Errorf("back=%q redirected to %q", back, loc)
		}
	}
}

// Applying stages files and leaves a request; it must not claim the change has
// reached the sensor, because it has not — a privileged step has to run first.
func TestApplyStagesAndSaysWhatIsHappening(t *testing.T) {
	srv, st, mgr := rulesServer(t)
	cookie := login(t, srv)

	if err := st.SetRulePolicy(store.RulePolicy{
		Scope: store.RuleScopeCategory, Key: "ET CINS",
		State: store.RuleStateDisabled, Actor: "admin",
	}); err != nil {
		t.Fatal(err)
	}

	rec := post(t, srv, cookie, "/rules/apply", url.Values{"reason": {"muted the feeds"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("apply POST = %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if strings.Contains(loc, "err=") {
		t.Fatalf("apply reported an error: %q", loc)
	}

	pending, _, err := mgr.Pending()
	if err != nil || !pending {
		t.Fatalf("no request was staged (pending=%v err=%v)", pending, err)
	}
	body, err := os.ReadFile(mgr.Paths().StagedDisable())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `re:msg:"ET CINS `) {
		t.Errorf("staged filters do not carry the decision:\n%s", body)
	}

	// A second apply while one is in flight is refused: two suricata-update
	// runs against the same data directory would race on the same output file.
	rec = post(t, srv, cookie, "/rules/apply", url.Values{})
	if !strings.Contains(rec.Header().Get("Location"), "err=") {
		t.Error("a second concurrent apply was accepted")
	}

	// And the page says so rather than looking idle.
	page := get(t, srv, cookie, "/rules").Body.String()
	if !strings.Contains(page, "Applying") {
		t.Error("the page does not show that an apply is in flight")
	}
}

// The one thing this feature must never grow. Suricata here is inline on
// NFQUEUE; dropping from it once cost 9.6% of transit traffic.
func TestNothingInTheUIOffersASuricataDrop(t *testing.T) {
	srv, _, _ := rulesServer(t)
	cookie := login(t, srv)

	for _, path := range []string{"/rules", "/rules?tab=catalogue", "/rules/2010371", "/settings?tab=suricata"} {
		body := get(t, srv, cookie, path).Body.String()
		for _, banned := range []string{"drop.conf", `value="drop"`, "name=\"drop\""} {
			if strings.Contains(body, banned) {
				t.Errorf("%s offers %q — blocking goes through nftably, never Suricata", path, banned)
			}
		}
	}
}

// isLocalPath guards the "back" parameter on every form in the console. It is
// worth its own table because the failure mode is an open redirect and the
// tricky cases do not look tricky.
func TestIsLocalPath(t *testing.T) {
	ok := []string{
		"/",
		"/rules",
		"/rules?tab=catalogue&q=ET+SCAN",
		"/sources/198.51.100.7",
		"/a/b/c",
	}
	for _, s := range ok {
		if !isLocalPath(s) {
			t.Errorf("isLocalPath(%q) = false, want true", s)
		}
	}

	bad := []string{
		"",
		"rules",
		"https://evil.example/",
		"//evil.example/",
		// Browsers normalise a backslash in the authority to a slash, so this
		// is fetched as //evil.example — a host, not a path.
		"/\\evil.example",
		"\\\\evil.example",
		// A control character can be stripped before the URL is parsed.
		"/\tevil.example",
		"/\nevil.example",
		"javascript:alert(1)",
	}
	for _, s := range bad {
		if isLocalPath(s) {
			t.Errorf("isLocalPath(%q) = true, want false", s)
		}
	}
}
