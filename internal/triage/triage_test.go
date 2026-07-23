package triage

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/floreabogdan/meerkat/internal/nftably"
	"github.com/floreabogdan/meerkat/internal/store"
)

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// fakeNftably applies the same rules nftably's real handler does.
type fakeNftably struct {
	blocked map[string]bool
	fail    bool
	srv     *httptest.Server
}

func newFakeNftably(t *testing.T) *fakeNftably {
	t.Helper()
	f := &fakeNftably{blocked: map[string]bool{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.fail {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if r.Header.Get("Authorization") != "Bearer secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var body struct{ IP, Note string }
		if r.Method == http.MethodPost {
			_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/block":
			if f.blocked[body.IP] {
				_ = json.NewEncoder(w).Encode(map[string]any{"blocked": body.IP, "already": true})
				return
			}
			f.blocked[body.IP] = true
			_ = json.NewEncoder(w).Encode(map[string]any{"blocked": body.IP, "note": "applied to the kernel"})
		case "/api/unblock":
			if !f.blocked[body.IP] {
				_ = json.NewEncoder(w).Encode(map[string]any{"unblocked": false, "reason": "not in the block list"})
				return
			}
			delete(f.blocked, body.IP)
			_ = json.NewEncoder(w).Encode(map[string]any{"unblocked": body.IP})
		case "/api/blocked":
			list := []map[string]string{}
			for ip := range f.blocked {
				list = append(list, map[string]string{"ip": ip, "note": ""})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"blocked": list})
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func setup(t *testing.T) (*Manager, *store.Store, *fakeNftably) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "meerkat.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	now := time.Now().UTC()
	mk := func(ip string, local bool) store.Alert {
		return store.Alert{
			Ts: now, SrcIP: ip, DestIP: "192.0.2.1", DestPort: 22, Proto: "TCP",
			SID: 2001219, Sig: "ET SCAN", Severity: 2, Action: "allowed", IsLocal: local,
		}
	}
	if err := st.RecordAlerts([]store.Alert{
		mk("198.51.100.7", false), mk("203.0.113.49", false), mk("192.168.1.50", true),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	f := newFakeNftably(t)
	m := New(st, nftably.New(f.srv.URL, "secret", "meerkat/test"), testLogger())
	return m, st, f
}

func TestBlockCallsNftablyThenRecords(t *testing.T) {
	m, st, f := setup(t)
	out, err := m.Block(context.Background(), "198.51.100.7", "ssh scanning", 0, "admin")
	if err != nil {
		t.Fatalf("block: %v", err)
	}
	if !f.blocked["198.51.100.7"] {
		t.Error("nftably was never asked to block it")
	}
	if !out.Live {
		t.Error("nftably said it applied to the kernel; that should surface as Live")
	}

	src, _ := st.GetSource("198.51.100.7")
	if src.State != store.StateBlocked {
		t.Errorf("state = %q, want blocked", src.State)
	}
	actions, _ := st.ActionsForTarget("198.51.100.7", 10)
	if len(actions) != 1 || !actions[0].OK || actions[0].Action != store.ActionBlock {
		t.Errorf("ledger = %+v", actions)
	}
}

// The rule the package exists for: if nftably fails, nothing may claim the
// address is blocked.
func TestFailedBlockNeverClaimsSuccess(t *testing.T) {
	m, st, f := setup(t)
	f.fail = true

	if _, err := m.Block(context.Background(), "198.51.100.7", "scanning", 0, "admin"); err == nil {
		t.Fatal("expected the block to fail")
	}
	src, _ := st.GetSource("198.51.100.7")
	if src.State == store.StateBlocked {
		t.Error("a source was marked blocked after nftably refused the call")
	}
	actions, _ := st.ActionsForTarget("198.51.100.7", 10)
	if len(actions) != 1 {
		t.Fatalf("the attempt should still be recorded: %+v", actions)
	}
	if actions[0].OK {
		t.Error("a failed attempt was recorded as successful")
	}
}

// Blocking one of our own addresses at the edge is a self-inflicted outage.
func TestLocalSourceCannotBeBlocked(t *testing.T) {
	m, st, f := setup(t)
	_, err := m.Block(context.Background(), "192.168.1.50", "looks noisy", 0, "admin")
	if err == nil {
		t.Fatal("expected a private address to be refused")
	}
	if !strings.Contains(err.Error(), "private") && !strings.Contains(err.Error(), "internal") {
		t.Errorf("the refusal should explain why: %v", err)
	}
	if f.blocked["192.168.1.50"] {
		t.Error("a private address reached nftably")
	}
	if src, _ := st.GetSource("192.168.1.50"); src.State == store.StateBlocked {
		t.Error("a private source was marked blocked")
	}
}

func TestUnblockLeavesSourceAcknowledged(t *testing.T) {
	m, st, f := setup(t)
	ctx := context.Background()
	if _, err := m.Block(ctx, "198.51.100.7", "scanning", 0, "admin"); err != nil {
		t.Fatalf("block: %v", err)
	}
	if _, err := m.Unblock(ctx, "198.51.100.7", "false positive", "admin"); err != nil {
		t.Fatalf("unblock: %v", err)
	}
	if f.blocked["198.51.100.7"] {
		t.Error("nftably still holds the block")
	}
	src, _ := st.GetSource("198.51.100.7")
	// Not "new": it has been looked at, and pretending otherwise would put it
	// back in the untriaged queue.
	if src.State != store.StateAcknowledged {
		t.Errorf("state after unblock = %q, want acknowledged", src.State)
	}
}

func TestTimedBlockExpires(t *testing.T) {
	m, st, f := setup(t)
	ctx := context.Background()
	if _, err := m.Block(ctx, "198.51.100.7", "burst", time.Millisecond, "admin"); err != nil {
		t.Fatalf("block: %v", err)
	}
	src, _ := st.GetSource("198.51.100.7")
	if src.BlockedUntil.IsZero() {
		t.Fatal("a timed block recorded no expiry")
	}

	time.Sleep(20 * time.Millisecond)
	m.ExpireBlocks(ctx)

	if f.blocked["198.51.100.7"] {
		t.Error("an expired block was not lifted in nftably")
	}
	src, _ = st.GetSource("198.51.100.7")
	if src.State == store.StateBlocked {
		t.Error("an expired block still reads as blocked")
	}
	if !src.BlockedUntil.IsZero() {
		t.Error("the expiry should be cleared once the block is lifted")
	}
}

// An indefinite block must not inherit a previous expiry.
func TestReblockingIndefinitelyClearsTheExpiry(t *testing.T) {
	m, st, _ := setup(t)
	ctx := context.Background()
	if _, err := m.Block(ctx, "198.51.100.7", "burst", time.Hour, "admin"); err != nil {
		t.Fatalf("block: %v", err)
	}
	if _, err := m.Block(ctx, "198.51.100.7", "persistent", 0, "admin"); err != nil {
		t.Fatalf("re-block: %v", err)
	}
	src, _ := st.GetSource("198.51.100.7")
	if !src.BlockedUntil.IsZero() {
		t.Errorf("BlockedUntil = %v, want cleared", src.BlockedUntil)
	}
}

// The firewall is the fact; meerkat's record is a memory. Reconcile corrects
// the memory, never the firewall.
func TestReconcileClearsAStaleBlock(t *testing.T) {
	m, st, f := setup(t)
	ctx := context.Background()
	if _, err := m.Block(ctx, "198.51.100.7", "scanning", 0, "admin"); err != nil {
		t.Fatalf("block: %v", err)
	}
	// Somebody removes it directly in nftably.
	delete(f.blocked, "198.51.100.7")

	if err := m.Reconcile(ctx); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	src, _ := st.GetSource("198.51.100.7")
	if src.State == store.StateBlocked {
		t.Error("meerkat still claims a source is blocked that nftably has released")
	}
	actions, _ := st.ActionsForTarget("198.51.100.7", 10)
	var sawDrift bool
	for _, a := range actions {
		if a.Actor == "reconcile" {
			sawDrift = true
		}
	}
	if !sawDrift {
		t.Error("the drift was corrected but not recorded; nobody could explain the change later")
	}
}

// And the other direction: banned by hand, so meerkat should say blocked.
func TestReconcileAdoptsAnExternalBlock(t *testing.T) {
	m, st, f := setup(t)
	f.blocked["203.0.113.49"] = true

	if err := m.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	src, _ := st.GetSource("203.0.113.49")
	if src.State != store.StateBlocked {
		t.Errorf("state = %q, want blocked — nftably is holding it", src.State)
	}
}

// Reconcile must not invent sources for addresses meerkat has never seen.
func TestReconcileIgnoresUnknownAddresses(t *testing.T) {
	m, st, f := setup(t)
	f.blocked["198.51.100.200"] = true

	if err := m.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if _, err := st.GetSource("198.51.100.200"); err != store.ErrNotFound {
		t.Error("reconcile created a source for an address that never alerted")
	}
}

// Acknowledging and allowlisting are local decisions and must not touch the
// firewall.
func TestLocalDecisionsDoNotTouchTheNetwork(t *testing.T) {
	m, st, f := setup(t)
	if err := m.Acknowledge("198.51.100.7", "known scanner", "admin"); err != nil {
		t.Fatalf("acknowledge: %v", err)
	}
	if err := m.Allowlist("203.0.113.49", "our monitoring", "admin"); err != nil {
		t.Fatalf("allowlist: %v", err)
	}
	if len(f.blocked) != 0 {
		t.Errorf("a local decision reached nftably: %v", f.blocked)
	}
	if src, _ := st.GetSource("198.51.100.7"); src.State != store.StateAcknowledged {
		t.Errorf("state = %q", src.State)
	}
	if src, _ := st.GetSource("203.0.113.49"); src.State != store.StateAllowlisted {
		t.Errorf("state = %q", src.State)
	}
}

func TestUnconfiguredManagerRefusesClearly(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "meerkat.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	m := New(st, nftably.New("", "", "meerkat/test"), testLogger())

	if m.CanBlock() {
		t.Error("CanBlock should be false without a configured nftably")
	}
	_, err = m.Block(context.Background(), "198.51.100.7", "", 0, "admin")
	if err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Errorf("got %v, want a clear 'not configured' error", err)
	}
	// Reconcile is a no-op rather than an error when blocking is off.
	if err := m.Reconcile(context.Background()); err != nil {
		t.Errorf("reconcile without nftably: %v", err)
	}
}
