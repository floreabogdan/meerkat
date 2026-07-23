package ingest

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/floreabogdan/meerkat/internal/eve"
	"github.com/floreabogdan/meerkat/internal/eve/evetest"
	"github.com/floreabogdan/meerkat/internal/geo"
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
	return st
}

// runIngest writes lines into an eve.json, runs the ingester over it from the
// start, and returns once everything has been written.
func runIngest(t *testing.T, st *store.Store, lines []string, cfg Config) *Ingester {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write eve.json: %v", err)
	}

	cfg.Store = st
	cfg.Log = testLogger()
	cfg.EvePath = path
	cfg.FromStart = true
	if cfg.BatchWait == 0 {
		cfg.BatchWait = 50 * time.Millisecond
	}
	in := New(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = in.Run(ctx)
	}()

	// Wait for the whole file to be written, not just read: Run only returns
	// after the writer has drained, so cancelling once the counts line up is
	// safe and keeps the test fast.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if s := in.Stats(); s.LinesRead >= uint64(len(lines)) && s.Written >= s.Alerts && s.Alerts > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("ingester did not stop")
	}
	return in
}

// The end-to-end test that matters: 386 captured alerts, through
// tail → prefilter → decode → enrich → rollup, with the resulting rollup checked
// against an independent recomputation from the same input.
func TestIngestRealAlertsRollsUpCorrectly(t *testing.T) {
	lines := evetest.AlertLines(t)
	st := openTestStore(t)
	in := runIngest(t, st, lines, Config{})

	stats := in.Stats()
	if stats.ParseErrors != 0 {
		t.Errorf("%d real lines failed to parse", stats.ParseErrors)
	}
	if stats.Alerts == 0 {
		t.Fatal("no alerts ingested")
	}
	if stats.Written != stats.Alerts {
		t.Errorf("wrote %d of %d alerts", stats.Written, stats.Alerts)
	}

	// Recompute the expected rollup straight from the fixture.
	type want struct {
		events    int64
		sigs      map[int]bool
		ports     map[string]bool
		worstSev  int
		firstSeen time.Time
		lastSeen  time.Time
	}
	expected := map[string]*want{}
	for _, line := range lines {
		ev, err := eve.Parse([]byte(line))
		if err != nil || ev.EventType != "alert" {
			continue
		}
		w := expected[ev.SrcIP]
		if w == nil {
			w = &want{sigs: map[int]bool{}, ports: map[string]bool{}, firstSeen: ev.Time(), lastSeen: ev.Time()}
			expected[ev.SrcIP] = w
		}
		w.events++
		if ev.Alert.SignatureID != 0 {
			w.sigs[ev.Alert.SignatureID] = true
		}
		if ev.DestPort != 0 {
			w.ports[ev.Proto+"/"+itoa(int64(ev.DestPort))] = true
		}
		if sev := ev.Alert.Severity; sev != 0 && (w.worstSev == 0 || sev < w.worstSev) {
			w.worstSev = sev
		}
		if ev.Time().Before(w.firstSeen) {
			w.firstSeen = ev.Time()
		}
		if ev.Time().After(w.lastSeen) {
			w.lastSeen = ev.Time()
		}
	}

	sources, total, err := st.ListSources(store.SourceFilter{Limit: 10000})
	if err != nil {
		t.Fatalf("list sources: %v", err)
	}
	if int(total) != len(expected) {
		t.Errorf("stored %d sources, recomputed %d", total, len(expected))
	}

	for _, got := range sources {
		w := expected[got.IP]
		if w == nil {
			t.Errorf("stored a source the fixture never mentions: %s", got.IP)
			continue
		}
		if got.EventCount != w.events {
			t.Errorf("%s: EventCount = %d, want %d", got.IP, got.EventCount, w.events)
		}
		if got.SigCount != len(w.sigs) {
			t.Errorf("%s: SigCount = %d, want %d", got.IP, got.SigCount, len(w.sigs))
		}
		if got.PortCount != len(w.ports) {
			t.Errorf("%s: PortCount = %d, want %d", got.IP, got.PortCount, len(w.ports))
		}
		if got.WorstSeverity != w.worstSev {
			t.Errorf("%s: WorstSeverity = %d, want %d", got.IP, got.WorstSeverity, w.worstSev)
		}
		if !got.FirstSeen.Equal(w.firstSeen.UTC().Truncate(time.Microsecond)) {
			t.Errorf("%s: FirstSeen = %v, want %v", got.IP, got.FirstSeen, w.firstSeen.UTC())
		}
		if !got.LastSeen.Equal(w.lastSeen.UTC().Truncate(time.Microsecond)) {
			t.Errorf("%s: LastSeen = %v, want %v", got.IP, got.LastSeen, w.lastSeen.UTC())
		}
	}

	t.Logf("%d alerts rolled up into %d sources", stats.Alerts, total)
}

// The premise the console rests on: far fewer sources than events, and far
// fewer signatures than either — so the useful unit is a source, not a row.
//
// Caveat on the fixture, because the numbers below will not match PLAN.md and
// that is not a bug: this capture predates the HOME_NET correction, so it holds
// 386 alerts from two hand-written local rules (SSH/RDP connection, sid
// 1000001-2) over 14 minutes, with no category set. The ET CINS / ET DROP
// reputation flood that motivates the per-signature disposition work was
// measured live and never written to a file. The skew this asserts is real and
// is the thing the rollup exploits; the category mix in PLAN.md is not
// reproduced here, and a fresh capture would be worth having before
// the muting work in Phase 3.
func TestRealAlertsAreDominatedByFewSignatures(t *testing.T) {
	st := openTestStore(t)
	runIngest(t, st, evetest.AlertLines(t), Config{})

	counts, err := st.Summary()
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	sigs, err := st.TopSignatures(5)
	if err != nil {
		t.Fatalf("top signatures: %v", err)
	}
	if len(sigs) == 0 {
		t.Fatal("no signatures recorded")
	}

	var top int64
	for _, s := range sigs {
		top += s.Hits
	}
	share := float64(top) / float64(counts.Events) * 100
	t.Logf("%d events, %d sources, %d signatures; top 5 signatures = %.1f%% of volume",
		counts.Events, counts.Sources, counts.Signatures, share)
	for _, s := range sigs {
		t.Logf("  %6d hits  sid %-8d %s", s.Hits, s.SID, s.Signature)
	}

	// 386 events from 66 sources: the home page shows 66 rows instead of 386,
	// and that ratio is what a live flood makes far starker.
	if counts.Sources*2 > counts.Events {
		t.Errorf("%d events from %d sources — too little skew for a per-source rollup to pay off",
			counts.Events, counts.Sources)
	}
	if share < 50 {
		t.Errorf("top 5 signatures are only %.1f%% of volume; the rollup premise assumed a heavy skew", share)
	}
}

// Enrichment must reach the source rows — a country column that is always empty
// makes the whole filter bar useless.
func TestIngestEnrichesSources(t *testing.T) {
	asn, country := "../geo/testdata/dbip-asn-lite.mmdb", "../geo/testdata/dbip-country-lite.mmdb"
	for _, p := range []string{asn, country} {
		if _, err := os.Stat(p); err != nil {
			t.Skipf("missing %s", p)
		}
	}
	enricher, err := geo.Open(asn, country, "")
	if err != nil {
		t.Fatalf("open enricher: %v", err)
	}
	defer enricher.Close()

	// Not the captured fixture: its addresses are documentation space, which by
	// design appears in no GeoIP database, so it could only ever prove that
	// nothing enriches. These are globally published anycast and cloud
	// addresses — the only real ones anywhere in this repo, and here because a
	// known-answer test against a real database needs real answers.
	st := openTestStore(t)
	runIngest(t, st, []string{
		alertLine("8.8.8.8", "192.0.2.1", 2001219, 22, 2),
		alertLine("1.1.1.1", "192.0.2.1", 2001219, 22, 2),
		alertLine("18.190.15.50", "192.0.2.1", 2001219, 22, 2),
		alertLine("192.168.1.50", "192.0.2.1", 2001219, 22, 2),
	}, Config{Geo: enricher})

	sources, _, err := st.ListSources(store.SourceFilter{Limit: 10000})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var enriched, local int
	for _, s := range sources {
		if s.IsLocal {
			local++
			continue
		}
		if s.Country != "" || s.ASN != 0 {
			enriched++
		}
	}
	public := len(sources) - local
	if public == 0 {
		t.Skip("the fixture has no public source addresses")
	}
	if enriched*2 < public {
		t.Errorf("only %d of %d public sources were enriched", enriched, public)
	}
	t.Logf("%d sources: %d enriched, %d local", len(sources), enriched, local)
}

// A private or CGNAT source is one of ours. It must be flagged, because it must
// never be blocked on reflex and must never leave the box on the public map.
func TestLocalSourcesAreFlagged(t *testing.T) {
	enricher, err := geo.Open("", "", "")
	if err != nil {
		t.Fatalf("open enricher: %v", err)
	}
	defer enricher.Close()

	st := openTestStore(t)
	runIngest(t, st, []string{
		alertLine("192.168.1.50", "192.0.2.1", 2001219, 22, 2),
		alertLine("100.64.0.9", "192.0.2.1", 2001219, 22, 2),
		alertLine("198.51.100.7", "192.0.2.1", 2001219, 22, 2),
	}, Config{Geo: enricher})

	for ip, wantLocal := range map[string]bool{
		"192.168.1.50": true, "100.64.0.9": true, "198.51.100.7": false,
	} {
		src, err := st.GetSource(ip)
		if err != nil {
			t.Fatalf("get %s: %v", ip, err)
		}
		if src.IsLocal != wantLocal {
			t.Errorf("%s: IsLocal = %v, want %v", ip, src.IsLocal, wantLocal)
		}
	}
}

// Non-alert records are the overwhelming majority of a real eve.json and must
// be dropped before they cost a JSON decode — and must never become sources.
func TestNonAlertRecordsAreIgnored(t *testing.T) {
	st := openTestStore(t)
	lines := []string{
		`{"timestamp":"2026-07-21T10:00:00.000000+0300","event_type":"flow","src_ip":"10.0.0.1","dest_ip":"8.8.8.8"}`,
		`{"timestamp":"2026-07-21T10:00:01.000000+0300","event_type":"stats","stats":{"uptime":42}}`,
		`{"timestamp":"2026-07-21T10:00:02.000000+0300","event_type":"dns","src_ip":"10.0.0.2"}`,
		alertLine("198.51.100.7", "192.0.2.1", 2001219, 22, 2),
	}
	in := runIngest(t, st, lines, Config{})

	stats := in.Stats()
	if stats.LinesRead != 4 {
		t.Errorf("read %d lines, want 4", stats.LinesRead)
	}
	if stats.Alerts != 1 {
		t.Errorf("kept %d alerts, want 1", stats.Alerts)
	}
	if stats.ParseErrors != 0 {
		t.Errorf("%d parse errors — non-alert lines should be rejected before decoding", stats.ParseErrors)
	}

	counts, _ := st.Summary()
	if counts.Sources != 1 {
		t.Errorf("%d sources, want 1 — only the alert's source counts", counts.Sources)
	}
}

// A corrupt line must be counted and skipped, not stop ingest.
func TestGarbageLinesAreSkipped(t *testing.T) {
	st := openTestStore(t)
	in := runIngest(t, st, []string{
		`{"event_type":"alert","this is not valid json`,
		alertLine("198.51.100.7", "192.0.2.1", 2001219, 22, 2),
	}, Config{})

	stats := in.Stats()
	if stats.ParseErrors != 1 {
		t.Errorf("ParseErrors = %d, want 1", stats.ParseErrors)
	}
	if stats.Written != 1 {
		t.Errorf("wrote %d alerts, want 1 — the good line must still land", stats.Written)
	}
	if stats.LastError == "" {
		t.Error("a parse failure should be visible in Stats().LastError")
	}
}

// Batching must not change the result: the same input across many small
// transactions has to produce the same rollup as one large one.
func TestBatchSizeDoesNotChangeTheRollup(t *testing.T) {
	lines := evetest.AlertLines(t)

	var results []map[string]int64
	for _, size := range []int{1, 7, 5000} {
		st := openTestStore(t)
		runIngest(t, st, lines, Config{BatchSize: size})
		sources, _, err := st.ListSources(store.SourceFilter{Limit: 10000})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		m := map[string]int64{}
		for _, s := range sources {
			m[s.IP] = s.EventCount*1000 + int64(s.SigCount)*10 + int64(s.PortCount)
		}
		results = append(results, m)
	}
	for i := 1; i < len(results); i++ {
		if len(results[i]) != len(results[0]) {
			t.Fatalf("batch size changed the source count: %d vs %d", len(results[i]), len(results[0]))
		}
		for ip, v := range results[0] {
			if results[i][ip] != v {
				t.Errorf("%s: rollup differs by batch size (%d vs %d)", ip, results[i][ip], v)
			}
		}
	}
}

// The protocol context blob is what distinguishes two alerts on the same rule
// from the same host, so it has to survive the trip.
func TestProtocolContextIsStored(t *testing.T) {
	st := openTestStore(t)
	line := `{"timestamp":"2026-07-21T10:00:00.000000+0300","event_type":"alert","src_ip":"198.51.100.7",` +
		`"src_port":44321,"dest_ip":"192.0.2.1","dest_port":80,"proto":"TCP","app_proto":"http",` +
		`"alert":{"action":"allowed","gid":1,"signature_id":2019401,"rev":3,"signature":"ET SCAN test",` +
		`"category":"Attempted Information Leak","severity":2},` +
		`"http":{"hostname":"example.com","url":"/admin","http_user_agent":"curl/8.0","http_method":"GET","status":404}}`
	runIngest(t, st, []string{line}, Config{})

	events, err := st.EventsForSource("198.51.100.7", 10)
	if err != nil || len(events) != 1 {
		t.Fatalf("events: %d, err %v", len(events), err)
	}
	var x extra
	if err := json.Unmarshal([]byte(events[0].Extra), &x); err != nil {
		t.Fatalf("extra is not valid JSON (%q): %v", events[0].Extra, err)
	}
	if x.HTTPHost != "example.com" || x.HTTPURL != "/admin" || x.UserAgent != "curl/8.0" {
		t.Errorf("protocol context lost: %+v", x)
	}
	if events[0].Action != "allowed" {
		t.Errorf("Action = %q — Suricata's own word must be kept verbatim", events[0].Action)
	}
}

// An alert with no protocol context — the common case — must not store an
// object full of empty strings for every one of 320k daily events.
func TestNoProtocolContextStoresNothing(t *testing.T) {
	st := openTestStore(t)
	runIngest(t, st, []string{alertLine("198.51.100.7", "192.0.2.1", 2001219, 22, 2)}, Config{})
	events, _ := st.EventsForSource("198.51.100.7", 10)
	if len(events) != 1 {
		t.Fatalf("got %d events", len(events))
	}
	if events[0].Extra != "" {
		t.Errorf("Extra = %q, want empty", events[0].Extra)
	}
}

// alertLine builds a minimal but realistic eve.json alert record.
func alertLine(src, dst string, sid, port, severity int) string {
	return `{"timestamp":"2026-07-21T10:00:00.000000+0300","event_type":"alert",` +
		`"src_ip":"` + src + `","src_port":44321,"dest_ip":"` + dst + `","dest_port":` + itoa(int64(port)) +
		`,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":` + itoa(int64(sid)) +
		`,"rev":1,"signature":"ET TEST rule","category":"Misc activity","severity":` + itoa(int64(severity)) + `}}`
}

// Every field of an enrichment has to reach the alert. This is a field-by-field
// check rather than a spot check because the failure mode is silent: a field
// nobody copies is simply zero, and a source with a city but no coordinates
// looks perfectly healthy right up until the threat map has nothing to plot.
// That exact bug shipped once.
func TestApplyGeoCopiesEveryField(t *testing.T) {
	g := geo.Geo{
		ASN: 15169, ASOrg: "Google LLC",
		Country: "US", CountryName: "United States", Continent: "NA",
		City: "Mountain View", Lat: 37.4220, Lon: -122.0850,
		Private: false,
	}
	var a store.Alert
	applyGeo(&a, g)

	checks := map[string]struct{ got, want any }{
		"ASN":         {a.ASN, g.ASN},
		"ASOrg":       {a.ASOrg, g.ASOrg},
		"Country":     {a.Country, g.Country},
		"CountryName": {a.CountryName, g.CountryName},
		"Continent":   {a.Continent, g.Continent},
		"City":        {a.City, g.City},
		"Lat":         {a.Lat, g.Lat},
		"Lon":         {a.Lon, g.Lon},
		"IsLocal":     {a.IsLocal, g.Private},
	}
	for name, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", name, c.got, c.want)
		}
	}

	// Guard against the reverse mistake: a new field on geo.Geo that nobody
	// wires through. If this count changes, applyGeo probably needs a line.
	if n := reflect.TypeOf(geo.Geo{}).NumField(); n != 9 {
		t.Errorf("geo.Geo has %d fields but applyGeo copies 9 — is a new one being dropped?", n)
	}

	// A private source must be marked, since that is what keeps it off the map.
	var priv store.Alert
	applyGeo(&priv, geo.Geo{Private: true})
	if !priv.IsLocal {
		t.Error("a private enrichment must set IsLocal")
	}
}

// The end-to-end version: with a city database loaded, a stored source must
// carry a plottable position.
func TestIngestStoresCoordinates(t *testing.T) {
	city := "../geo/testdata/dbip-city-lite.mmdb"
	if _, err := os.Stat(city); err != nil {
		t.Skip("no city database in testdata; TestApplyGeoCopiesEveryField covers the mapping")
	}
	enricher, err := geo.Open("", "", city)
	if err != nil {
		t.Fatalf("open enricher: %v", err)
	}
	defer enricher.Close()

	st := openTestStore(t)
	runIngest(t, st, []string{alertLine("8.8.8.8", "192.0.2.1", 2001219, 22, 2)}, Config{Geo: enricher})

	src, err := st.GetSource("8.8.8.8")
	if err != nil {
		t.Fatalf("get source: %v", err)
	}
	if src.Lat == 0 && src.Lon == 0 {
		t.Error("a source enriched from a city database has no coordinates; it cannot be plotted")
	}
}
