package web

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/floreabogdan/meerkat/internal/nftably"
	"github.com/floreabogdan/meerkat/internal/store"
	"github.com/floreabogdan/meerkat/internal/triage"
)

// blockingServer is a test server with a working nftably behind it, so the
// action handlers run against the same responses the real one gives.
func blockingServer(t *testing.T) (*Server, *store.Store, map[string]bool) {
	t.Helper()
	blocked := map[string]bool{}
	nftSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct{ IP, Note string }
		if r.Method == http.MethodPost {
			_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/block":
			blocked[body.IP] = true
			_ = json.NewEncoder(w).Encode(map[string]any{"blocked": body.IP, "note": "applied to the kernel"})
		case "/api/unblock":
			delete(blocked, body.IP)
			_ = json.NewEncoder(w).Encode(map[string]any{"unblocked": body.IP})
		case "/api/blocked":
			list := []map[string]string{}
			for ip := range blocked {
				list = append(list, map[string]string{"ip": ip})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"blocked": list})
		}
	}))
	t.Cleanup(nftSrv.Close)

	st, err := store.Open(filepath.Join(t.TempDir(), "meerkat.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.SaveIdentity("edge1", "0.0.0.0:8100"); err != nil {
		t.Fatalf("identity: %v", err)
	}
	hash, _ := HashPassword("correct horse battery")
	if _, err := st.CreateUser("admin", hash); err != nil {
		t.Fatalf("user: %v", err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(Config{
		Store:      st,
		Log:        log,
		ListenAddr: "127.0.0.1:8100",
		DataDir:    t.TempDir(),
		Triage:     triage.New(st, nftably.New(nftSrv.URL, "tok", "meerkat/test"), log),
	})
	seed(t, st)
	return srv, st, blocked
}

func TestBlockFromTheUI(t *testing.T) {
	srv, st, blocked := blockingServer(t)
	cookie := login(t, srv)

	rec := post(t, srv, cookie, "/sources/198.51.100.7/block",
		url.Values{"reason": {"ssh scanning"}, "ttl": {""}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("block = %d", rec.Code)
	}
	if !blocked["198.51.100.7"] {
		t.Error("nftably was never asked to block it")
	}
	src, _ := st.GetSource("198.51.100.7")
	if src.State != store.StateBlocked {
		t.Errorf("state = %q, want blocked", src.State)
	}

	// The ledger carries the reason, so the decision is explainable later.
	actions, _ := st.ActionsForTarget("198.51.100.7", 5)
	if len(actions) == 0 || actions[0].Reason != "ssh scanning" {
		t.Errorf("ledger = %+v", actions)
	}

	if rec := post(t, srv, cookie, "/sources/198.51.100.7/unblock", url.Values{"reason": {"false positive"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("unblock = %d", rec.Code)
	}
	if blocked["198.51.100.7"] {
		t.Error("nftably still holds the block")
	}
}

// The non-negotiable, exercised through the real HTTP path: nftably down means
// nothing gets marked blocked.
func TestUIBlockFailureDoesNotClaimSuccess(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer dead.Close()

	st, err := store.Open(filepath.Join(t.TempDir(), "meerkat.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_ = st.SaveIdentity("edge1", "0.0.0.0:8100")
	hash, _ := HashPassword("correct horse battery")
	_, _ = st.CreateUser("admin", hash)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(Config{Store: st, Log: log, ListenAddr: "127.0.0.1:8100", DataDir: t.TempDir(),
		Triage: triage.New(st, nftably.New(dead.URL, "tok", "meerkat/test"), log)})
	seed(t, st)
	cookie := login(t, srv)

	rec := post(t, srv, cookie, "/sources/198.51.100.7/block", url.Values{"reason": {"scanning"}})
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "err=") {
		t.Errorf("a failed block did not surface an error: %q", loc)
	}
	src, _ := st.GetSource("198.51.100.7")
	if src.State == store.StateBlocked {
		t.Fatal("a source was marked blocked after nftably refused the call")
	}
}

// Blocking one of our own addresses would be a self-inflicted outage.
func TestUIRefusesToBlockALocalSource(t *testing.T) {
	srv, st, blocked := blockingServer(t)
	cookie := login(t, srv)

	rec := post(t, srv, cookie, "/sources/192.168.1.50/block", url.Values{"reason": {"noisy"}})
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "err=") {
		t.Errorf("blocking a private address should be refused: %q", loc)
	}
	if blocked["192.168.1.50"] {
		t.Error("a private address reached nftably")
	}
	if src, _ := st.GetSource("192.168.1.50"); src.State == store.StateBlocked {
		t.Error("a private source was marked blocked")
	}
}

func TestAcknowledgeAndAllowlistFromTheUI(t *testing.T) {
	srv, st, blocked := blockingServer(t)
	cookie := login(t, srv)

	post(t, srv, cookie, "/sources/198.51.100.7/acknowledge", url.Values{"reason": {"known scanner"}})
	post(t, srv, cookie, "/sources/203.0.113.49/allowlist", url.Values{"reason": {"our monitoring"}})

	if src, _ := st.GetSource("198.51.100.7"); src.State != store.StateAcknowledged {
		t.Errorf("state = %q, want acknowledged", src.State)
	}
	if src, _ := st.GetSource("203.0.113.49"); src.State != store.StateAllowlisted {
		t.Errorf("state = %q, want allowlisted", src.State)
	}
	if len(blocked) != 0 {
		t.Errorf("a local decision reached the firewall: %v", blocked)
	}
}

func TestBulkActions(t *testing.T) {
	srv, st, blocked := blockingServer(t)
	cookie := login(t, srv)

	rec := post(t, srv, cookie, "/sources/bulk", url.Values{
		"action": {"block"}, "reason": {"sweep"},
		"ip": {"198.51.100.7", "203.0.113.49"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("bulk = %d", rec.Code)
	}
	if !blocked["198.51.100.7"] || !blocked["203.0.113.49"] {
		t.Errorf("bulk block missed one: %v", blocked)
	}
	for _, ip := range []string{"198.51.100.7", "203.0.113.49"} {
		if src, _ := st.GetSource(ip); src.State != store.StateBlocked {
			t.Errorf("%s state = %q", ip, src.State)
		}
	}

	// A partial failure must be reported, not rounded up to success: the local
	// address in this selection cannot be blocked.
	rec = post(t, srv, cookie, "/sources/bulk", url.Values{
		"action": {"block"}, "ip": {"198.51.100.7", "192.168.1.50"},
	})
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "err=") || !strings.Contains(loc, "failed") {
		t.Errorf("a partly-failed bulk action should say so: %q", loc)
	}
}

// A bulk action is one firewall call per address, so it is capped.
func TestBulkIsCapped(t *testing.T) {
	srv, _, blocked := blockingServer(t)
	cookie := login(t, srv)

	ips := make([]string, 0, maxBulk+1)
	for i := range maxBulk + 1 {
		ips = append(ips, "198.51.100."+itoa(i+1))
	}
	rec := post(t, srv, cookie, "/sources/bulk", url.Values{"action": {"block"}, "ip": ips})
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "err=") {
		t.Errorf("an oversized bulk action should be refused: %q", loc)
	}
	if len(blocked) != 0 {
		t.Errorf("an oversized bulk action still hit the firewall: %v", blocked)
	}
}

func TestBulkWithNothingSelected(t *testing.T) {
	srv, _, _ := blockingServer(t)
	cookie := login(t, srv)
	rec := post(t, srv, cookie, "/sources/bulk", url.Values{"action": {"block"}})
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "err=") {
		t.Errorf("an empty selection should be refused: %q", loc)
	}
}

// The action endpoints are POST-only and behind the session, like every other
// write in the app.
func TestActionEndpointsRequireAuthAndPost(t *testing.T) {
	srv, _, blocked := blockingServer(t)

	for _, p := range []string{
		"/sources/198.51.100.7/block", "/sources/198.51.100.7/unblock",
		"/sources/198.51.100.7/acknowledge", "/sources/198.51.100.7/allowlist",
		"/sources/bulk", "/signatures/disposition",
	} {
		if rec := post(t, srv, nil, p, url.Values{"action": {"block"}}); rec.Code != http.StatusSeeOther ||
			rec.Header().Get("Location") != "/login" {
			t.Errorf("POST %s without a session = %d %q", p, rec.Code, rec.Header().Get("Location"))
		}
		if rec := get(t, srv, nil, p); rec.Code == http.StatusOK {
			t.Errorf("GET %s returned 200; actions must be POST-only", p)
		}
	}
	if len(blocked) != 0 {
		t.Errorf("an unauthenticated request reached the firewall: %v", blocked)
	}
}

// A path segment that is not an address must never reach the store or nftably.
func TestActionRejectsNonAddressPath(t *testing.T) {
	srv, _, blocked := blockingServer(t)
	cookie := login(t, srv)
	if rec := post(t, srv, cookie, "/sources/not-an-address/block", url.Values{}); rec.Code != http.StatusNotFound {
		t.Errorf("got %d, want 404", rec.Code)
	}
	if len(blocked) != 0 {
		t.Errorf("a malformed target reached the firewall: %v", blocked)
	}
}

// The "back" parameter is attacker-influencable and must stay on this site.
func TestActionRedirectIsNotAnOpenRedirect(t *testing.T) {
	srv, _, _ := blockingServer(t)
	cookie := login(t, srv)
	for _, back := range []string{"https://evil.example/x", "//evil.example/x"} {
		rec := post(t, srv, cookie, "/sources/198.51.100.7/acknowledge", url.Values{"back": {back}})
		if loc := rec.Header().Get("Location"); strings.Contains(loc, "evil.example") {
			t.Errorf("back=%q produced an off-site redirect: %q", back, loc)
		}
	}
}

func TestSignatureDisposition(t *testing.T) {
	srv, st, _ := blockingServer(t)
	cookie := login(t, srv)

	rec := post(t, srv, cookie, "/signatures/disposition",
		url.Values{"sid": {"2001219"}, "disposition": {"mute"}, "back": {"/signatures"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("disposition = %d", rec.Code)
	}
	sigs, _ := st.TopSignatures(10)
	var found bool
	for _, sig := range sigs {
		if sig.SID == 2001219 {
			found = true
			if sig.Disposition != store.DispositionMute {
				t.Errorf("disposition = %q, want mute", sig.Disposition)
			}
		}
	}
	if !found {
		t.Fatal("signature 2001219 not present")
	}

	rec = post(t, srv, cookie, "/signatures/disposition",
		url.Values{"sid": {"2001219"}, "disposition": {"shout"}})
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "err=") {
		t.Errorf("an unknown disposition should be refused: %q", loc)
	}
}

// Without nftably configured, the source page explains itself instead of
// offering a button that always fails.
func TestSourcePageExplainsWhenBlockingIsUnconfigured(t *testing.T) {
	srv, st := testServer(t)
	seed(t, st)
	cookie := login(t, srv)

	body := get(t, srv, cookie, "/sources/198.51.100.7").Body.String()
	if !strings.Contains(body, "Blocking is not configured") {
		t.Error("the source page should say blocking is unconfigured")
	}
	if strings.Contains(body, `action="/sources/198.51.100.7/block"`) {
		t.Error("a block button was offered with no nftably configured")
	}
}
