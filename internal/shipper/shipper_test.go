package shipper

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/floreabogdan/meerkat/internal/store"
)

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "meerkat.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.SaveIdentity("edge1", "0.0.0.0:8100"); err != nil {
		t.Fatalf("identity: %v", err)
	}
	return st
}

// collector is a stand-in for the website's /api/threats/ingest, applying the
// same rules its real handler does: bearer auth, gzip body, batch cap.
type collector struct {
	mu       sync.Mutex
	batches  []payload
	token    string
	status   int // when non-zero, respond with this instead of accepting
	failNext int // fail this many requests, then start accepting
	srv      *httptest.Server
}

func newCollector(t *testing.T, token string) *collector {
	t.Helper()
	c := &collector{token: token}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+c.token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		c.mu.Lock()
		if c.failNext > 0 {
			c.failNext--
			c.mu.Unlock()
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		status := c.status
		c.mu.Unlock()
		if status != 0 {
			w.WriteHeader(status)
			return
		}

		body := io.Reader(r.Body)
		if r.Header.Get("Content-Encoding") == "gzip" {
			zr, err := gzip.NewReader(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			defer zr.Close()
			body = zr
		}
		var p payload
		if err := json.NewDecoder(body).Decode(&p); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if len(p.Events) > maxBatch {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		c.mu.Lock()
		c.batches = append(c.batches, p)
		c.mu.Unlock()
		_, _ = w.Write([]byte(`{"inserted":` + itoa(len(p.Events)) + `}`))
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func (c *collector) all() []Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []Event
	for _, b := range c.batches {
		out = append(out, b.Events...)
	}
	return out
}

func (c *collector) sites() []Site {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []Site
	for _, b := range c.batches {
		out = append(out, b.Site)
	}
	return out
}

func alert(ip string, at time.Time) store.Alert {
	return store.Alert{
		Ts: at, SrcIP: ip, DestIP: "192.0.2.42", DestPort: 22, Proto: "TCP",
		SID: 2001219, Sig: "ET SCAN Potential SSH Scan", Category: "Attempted Information Leak",
		Severity: 2, Action: "allowed",
		Country: "RO", CountryName: "Romania", City: "Bucharest",
		Lat: 44.43, Lon: 26.10, ASN: 64500, ASOrg: "Example Telecom",
	}
}

func newShipper(t *testing.T, st *store.Store, url, token string) *Shipper {
	t.Helper()
	// The operator's own public space, as an operator would set it, plus the
	// private ranges meerkat withholds by default.
	nets, errs := ParseHomeNets("192.0.2.0/24\n2001:db8::/32\n" + DefaultHomeNets)
	if len(errs) > 0 {
		t.Fatalf("home nets do not parse: %v", errs)
	}
	return New(Config{
		Store: st, Log: testLogger(), URL: url, Token: token,
		Site:      Site{Name: "Example Site", Country: "RO", Lat: 44.86, Lng: 24.87},
		HomeNets:  nets,
		UserAgent: "meerkat/test",
		Batch:     100,
	})
}

func TestShipsEnrichedEvents(t *testing.T) {
	st := openTestStore(t)
	c := newCollector(t, "secret")
	if err := st.RecordAlerts([]store.Alert{alert("198.51.100.7", time.Now().UTC())}); err != nil {
		t.Fatalf("record: %v", err)
	}

	s := newShipper(t, st, c.srv.URL, "secret")
	if _, err := s.shipOnce(context.Background()); err != nil {
		t.Fatalf("ship: %v", err)
	}

	got := c.all()
	if len(got) != 1 {
		t.Fatalf("collector received %d events, want 1", len(got))
	}
	e := got[0]
	if e.SrcIP != "198.51.100.7" || e.SID != 2001219 || e.Sev != 2 || e.DPort != 22 {
		t.Errorf("event = %+v", e)
	}
	if e.SrcCC != "RO" || e.SrcCit != "Bucharest" || e.SrcASN != 64500 || e.SrcOrg != "Example Telecom" {
		t.Errorf("enrichment did not survive: %+v", e)
	}
	if e.SrcLat == 0 || e.SrcLng == 0 {
		t.Errorf("coordinates missing: %+v", e)
	}
	if e.Action != "detected" {
		t.Errorf("action = %q, want detected", e.Action)
	}
	if sites := c.sites(); len(sites) != 1 || sites[0].Name != "Example Site" {
		t.Errorf("site = %+v", sites)
	}
}

// The single most important test in this package. The public map must never
// carry a customer address, and a source inside our own ranges is a customer
// or one of our hosts.
func TestNeverPublishesOurOwnAddresses(t *testing.T) {
	st := openTestStore(t)
	c := newCollector(t, "secret")

	now := time.Now().UTC()
	ours := []string{
		"192.0.2.42",   // our own public space
		"2001:db8::5",  // our own v6
		"10.4.4.4",     // RFC1918
		"192.168.1.50", // RFC1918
		"172.16.9.9",   // RFC1918
	}
	var batch []store.Alert
	for i, ip := range ours {
		batch = append(batch, alert(ip, now.Add(time.Duration(i)*time.Second)))
	}
	// One genuine outsider, so the test proves suppression rather than silence.
	batch = append(batch, alert("198.51.100.7", now.Add(time.Hour)))
	if err := st.RecordAlerts(batch); err != nil {
		t.Fatalf("record: %v", err)
	}

	s := newShipper(t, st, c.srv.URL, "secret")
	if _, err := s.shipOnce(context.Background()); err != nil {
		t.Fatalf("ship: %v", err)
	}

	got := c.all()
	if len(got) != 1 {
		t.Fatalf("published %d events, want only the external one: %+v", len(got), got)
	}
	if got[0].SrcIP != "198.51.100.7" {
		t.Errorf("published %q", got[0].SrcIP)
	}
	for _, e := range got {
		for _, ip := range ours {
			if e.SrcIP == ip {
				t.Errorf("published one of our own addresses: %s", ip)
			}
		}
	}
	if s.Stats().Withheld == 0 {
		t.Error("suppression should be counted, so it is visible rather than silent")
	}
}

// The destination is reported as a site name and a port. There must be no way
// for a customer address to reach the wire at all.
func TestDestinationAddressIsNeverOnTheWire(t *testing.T) {
	st := openTestStore(t)
	c := newCollector(t, "secret")
	a := alert("198.51.100.7", time.Now().UTC())
	a.DestIP = "192.0.2.99" // a customer host being probed
	if err := st.RecordAlerts([]store.Alert{a}); err != nil {
		t.Fatalf("record: %v", err)
	}

	s := newShipper(t, st, c.srv.URL, "secret")
	if _, err := s.shipOnce(context.Background()); err != nil {
		t.Fatalf("ship: %v", err)
	}

	// Check the serialised form, not the struct: a field added later with the
	// wrong intent would show up here.
	raw, err := json.Marshal(payload{Site: s.cfg.Site, Events: []Event{{SrcIP: "x"}}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "dest") || strings.Contains(string(raw), "destIP") {
		t.Errorf("the wire format has a destination field: %s", raw)
	}
	for _, e := range c.all() {
		blob, _ := json.Marshal(e)
		if strings.Contains(string(blob), "192.0.2.99") {
			t.Errorf("a destination address reached the wire: %s", blob)
		}
	}
}

// "blocked" may only mean actually banned in nftables.
func TestActionReflectsRealBlockState(t *testing.T) {
	st := openTestStore(t)
	c := newCollector(t, "secret")
	now := time.Now().UTC()
	if err := st.RecordAlerts([]store.Alert{
		alert("198.51.100.7", now),
		alert("203.0.113.49", now.Add(time.Second)),
	}); err != nil {
		t.Fatalf("record: %v", err)
	}
	// Only this one was actually banned.
	if err := st.SetSourceState("203.0.113.49", store.StateBlocked, "confirmed in nftables", "admin"); err != nil {
		t.Fatalf("state: %v", err)
	}

	s := newShipper(t, st, c.srv.URL, "secret")
	if _, err := s.shipOnce(context.Background()); err != nil {
		t.Fatalf("ship: %v", err)
	}

	actions := map[string]string{}
	for _, e := range c.all() {
		actions[e.SrcIP] = e.Action
	}
	if actions["198.51.100.7"] != "detected" {
		t.Errorf("an un-banned source reported as %q", actions["198.51.100.7"])
	}
	if actions["203.0.113.49"] != "blocked" {
		t.Errorf("a banned source reported as %q", actions["203.0.113.49"])
	}

	// Acknowledged is a triage note, not a firewall state.
	if err := st.SetSourceState("198.51.100.7", store.StateAcknowledged, "known scanner", "admin"); err != nil {
		t.Fatalf("state: %v", err)
	}
	if err := st.RecordAlerts([]store.Alert{alert("198.51.100.7", now.Add(time.Minute))}); err != nil {
		t.Fatalf("record: %v", err)
	}
	if _, err := s.shipOnce(context.Background()); err != nil {
		t.Fatalf("ship: %v", err)
	}
	last := c.all()
	if a := last[len(last)-1].Action; a != "detected" {
		t.Errorf("acknowledged source reported as %q, want detected", a)
	}
}

// The cursor is what makes publishing exactly-once across restarts.
func TestCursorAdvancesAndPreventsRepublishing(t *testing.T) {
	st := openTestStore(t)
	c := newCollector(t, "secret")
	now := time.Now().UTC()
	if err := st.RecordAlerts([]store.Alert{
		alert("198.51.100.7", now),
		alert("198.51.100.8", now.Add(time.Second)),
	}); err != nil {
		t.Fatalf("record: %v", err)
	}

	s := newShipper(t, st, c.srv.URL, "secret")
	if _, err := s.shipOnce(context.Background()); err != nil {
		t.Fatalf("ship: %v", err)
	}
	if n := len(c.all()); n != 2 {
		t.Fatalf("first pass published %d, want 2", n)
	}

	// Nothing new: a second pass must publish nothing.
	if _, err := s.shipOnce(context.Background()); err != nil {
		t.Fatalf("second ship: %v", err)
	}
	if n := len(c.all()); n != 2 {
		t.Errorf("re-published history: total is now %d", n)
	}

	// A fresh Shipper (as after a restart) reads the persisted cursor.
	if err := st.RecordAlerts([]store.Alert{alert("198.51.100.9", now.Add(time.Minute))}); err != nil {
		t.Fatalf("record: %v", err)
	}
	s2 := newShipper(t, st, c.srv.URL, "secret")
	if _, err := s2.shipOnce(context.Background()); err != nil {
		t.Fatalf("restarted ship: %v", err)
	}
	got := c.all()
	if len(got) != 3 || got[2].SrcIP != "198.51.100.9" {
		t.Errorf("after restart, published %d events ending %q", len(got), got[len(got)-1].SrcIP)
	}
}

// A failed POST must not advance the cursor, or the batch is lost for good.
func TestFailedBatchIsRetriedNotLost(t *testing.T) {
	st := openTestStore(t)
	c := newCollector(t, "secret")
	c.status = http.StatusServiceUnavailable

	if err := st.RecordAlerts([]store.Alert{alert("198.51.100.7", time.Now().UTC())}); err != nil {
		t.Fatalf("record: %v", err)
	}
	s := newShipper(t, st, c.srv.URL, "secret")
	// Retries are backed off; a short deadline keeps the test quick and still
	// exercises the "did not advance" path.
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	if _, err := s.shipOnce(ctx); err == nil {
		t.Fatal("expected the batch to fail")
	}
	cancel()

	settings, _, _ := st.GetSettings()
	if settings.ThreatsCursor != 0 {
		t.Errorf("cursor advanced past a failed batch: %d", settings.ThreatsCursor)
	}
	if s.Stats().LastError == "" {
		t.Error("a failure should be visible in Stats")
	}

	// Once the collector recovers, the same batch goes out.
	c.mu.Lock()
	c.status = 0
	c.mu.Unlock()
	if _, err := s.shipOnce(context.Background()); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if n := len(c.all()); n != 1 {
		t.Errorf("after recovery the collector has %d events, want 1", n)
	}
}

// A transient 5xx should be ridden out by the retry loop without the caller
// ever seeing a failure.
func TestTransientFailureIsRetriedInline(t *testing.T) {
	st := openTestStore(t)
	c := newCollector(t, "secret")
	c.failNext = 1

	if err := st.RecordAlerts([]store.Alert{alert("198.51.100.7", time.Now().UTC())}); err != nil {
		t.Fatalf("record: %v", err)
	}
	s := newShipper(t, st, c.srv.URL, "secret")
	if _, err := s.shipOnce(context.Background()); err != nil {
		t.Fatalf("ship should have survived one 502: %v", err)
	}
	if n := len(c.all()); n != 1 {
		t.Errorf("collector has %d events, want 1", n)
	}
}

// A bad token is not transient; it must fail fast rather than burn the backoff.
func TestBadTokenFailsWithoutRetrying(t *testing.T) {
	st := openTestStore(t)
	c := newCollector(t, "secret")
	if err := st.RecordAlerts([]store.Alert{alert("198.51.100.7", time.Now().UTC())}); err != nil {
		t.Fatalf("record: %v", err)
	}
	s := newShipper(t, st, c.srv.URL, "wrong-token")

	start := time.Now()
	_, err := s.shipOnce(context.Background())
	if err == nil {
		t.Fatal("expected a rejection")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("a 401 was retried with backoff (%v); it will never succeed", elapsed)
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error should name the status: %v", err)
	}
}

// The body has to actually be gzip, because the collector decodes by header.
func TestBodyIsGzipped(t *testing.T) {
	st := openTestStore(t)
	var sawEncoding, sawType string
	var raw []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawEncoding = r.Header.Get("Content-Encoding")
		sawType = r.Header.Get("Content-Type")
		raw, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	if err := st.RecordAlerts([]store.Alert{alert("198.51.100.7", time.Now().UTC())}); err != nil {
		t.Fatalf("record: %v", err)
	}
	s := newShipper(t, st, srv.URL, "secret")
	if _, err := s.shipOnce(context.Background()); err != nil {
		t.Fatalf("ship: %v", err)
	}

	if sawEncoding != "gzip" {
		t.Errorf("Content-Encoding = %q", sawEncoding)
	}
	if sawType != "application/json" {
		t.Errorf("Content-Type = %q", sawType)
	}
	if len(raw) < 2 || raw[0] != 0x1f || raw[1] != 0x8b {
		t.Errorf("body is not gzip: % x", raw[:min(8, len(raw))])
	}
	zr, err := gzip.NewReader(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	defer zr.Close()
	var p payload
	if err := json.NewDecoder(zr).Decode(&p); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(p.Events) != 1 {
		t.Errorf("decoded %d events", len(p.Events))
	}
}

// Batches must stay under the collector's hard cap.
func TestBatchIsCapped(t *testing.T) {
	if got := New(Config{Batch: 99999}).cfg.Batch; got > maxBatch {
		t.Errorf("batch of %d exceeds the collector's cap of %d", got, maxBatch)
	}
	if got := New(Config{Batch: 0}).cfg.Batch; got <= 0 || got > maxBatch {
		t.Errorf("default batch %d is not usable", got)
	}
}

// An empty home-nets setting must fall back to the defaults. Failing open here
// would publish customer addresses.
func TestEmptyHomeNetsFallsBackToDefaults(t *testing.T) {
	nets, errs := ParseHomeNets("   \n  \n")
	if len(errs) > 0 {
		t.Fatalf("defaults do not parse: %v", errs)
	}
	if len(nets) == 0 {
		t.Fatal("an empty setting produced no home networks; customer addresses would be published")
	}
	s := New(Config{HomeNets: nets})
	// The default covers private and carrier-internal space only. Public
	// prefixes are the operator's to add — meerkat cannot guess them, and a
	// default carrying somebody else's ranges would be worse than none.
	for _, ip := range []string{"10.0.0.1", "192.168.0.1", "172.16.0.1", "100.64.0.1", "fc00::1"} {
		if !s.isOurs(ip) {
			t.Errorf("%s should be recognised as ours by default", ip)
		}
	}
	if s.isOurs("8.8.8.8") {
		t.Error("8.8.8.8 is not ours")
	}
}

// An address that cannot be parsed cannot be shown to be safe to publish.
func TestUnparseableSourceIsWithheld(t *testing.T) {
	nets, _ := ParseHomeNets("")
	s := New(Config{HomeNets: nets})
	if !s.isOurs("not-an-address") {
		t.Error("an unparseable source should be withheld, not published")
	}
}

// A run of suppressed events must still move the cursor, or the shipper reads
// the same rows forever and never reaches the events after them.
func TestSuppressedRunStillAdvancesTheCursor(t *testing.T) {
	st := openTestStore(t)
	c := newCollector(t, "secret")
	now := time.Now().UTC()
	var batch []store.Alert
	for i := range 5 {
		batch = append(batch, alert("10.0.0."+itoa(i+1), now.Add(time.Duration(i)*time.Second)))
	}
	if err := st.RecordAlerts(batch); err != nil {
		t.Fatalf("record: %v", err)
	}

	s := newShipper(t, st, c.srv.URL, "secret")
	if _, err := s.shipOnce(context.Background()); err != nil {
		t.Fatalf("ship: %v", err)
	}
	if n := len(c.all()); n != 0 {
		t.Fatalf("published %d private-source events", n)
	}
	settings, _, _ := st.GetSettings()
	if settings.ThreatsCursor == 0 {
		t.Error("cursor did not advance past a fully suppressed batch; it would loop forever")
	}
}

// The connectivity test must never put a real host on the public map.
func TestConnectivityTestUsesADocumentationAddress(t *testing.T) {
	st := openTestStore(t)
	c := newCollector(t, "secret")
	s := newShipper(t, st, c.srv.URL, "secret")
	if err := s.Test(context.Background()); err != nil {
		t.Fatalf("test: %v", err)
	}
	got := c.all()
	if len(got) != 1 {
		t.Fatalf("got %d events", len(got))
	}
	// RFC 5737 TEST-NET-1.
	if !strings.HasPrefix(got[0].SrcIP, "192.0.2.") {
		t.Errorf("connectivity test published %q, want a documentation address", got[0].SrcIP)
	}
}
