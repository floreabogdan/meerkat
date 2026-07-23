package store

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "meerkat.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestOpenIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "meerkat.db")
	for i := range 3 {
		st, err := Open(path)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		if err := st.CheckWritable(); err != nil {
			t.Fatalf("writable %d: %v", i, err)
		}
		st.Close()
	}
}

// The stored timestamp format has to be fixed-width, because MIN()/MAX() and
// every ORDER BY in this package compare these columns as TEXT. time.RFC3339Nano
// trims trailing zeros, which would make an event half a second later sort
// *earlier* than one on the whole second (".5Z" < "Z" bytewise). This is the
// regression test for that.
func TestTimeFormatIsLexicographicallyOrdered(t *testing.T) {
	base := time.Date(2026, 7, 21, 10, 0, 0, 0, time.UTC)
	times := []time.Time{
		base,
		base.Add(500 * time.Millisecond),
		base.Add(time.Second),
		base.Add(90 * time.Second),
		base.Add(25 * time.Hour),
	}
	for i := 1; i < len(times); i++ {
		prev, cur := FormatTime(times[i-1]), FormatTime(times[i])
		if len(prev) != len(cur) {
			t.Fatalf("format is not fixed width: %q (%d) vs %q (%d)", prev, len(prev), cur, len(cur))
		}
		if prev >= cur {
			t.Errorf("%q should sort before %q", prev, cur)
		}
	}
}

func TestFormatParseRoundTrip(t *testing.T) {
	want := time.Date(2026, 7, 21, 16, 58, 9, 531955000, time.UTC)
	if got := ParseTime(FormatTime(want)); !got.Equal(want) {
		t.Errorf("round trip: got %v, want %v", got, want)
	}
	if got := ParseTime(""); !got.IsZero() {
		t.Errorf("empty should parse to the zero time, got %v", got)
	}
}

// alert builds a minimal alert for the rollup tests.
func alert(ip string, sid int, port int, severity int, at time.Time) Alert {
	return Alert{
		Ts: at, SrcIP: ip, DestIP: "192.0.2.1", DestPort: port, Proto: "TCP",
		SID: sid, Sig: "ET TEST signature", Category: "Misc", Severity: severity,
		Action: "allowed", Country: "US", ASN: 15169, ASOrg: "GOOGLE",
	}
}

func TestRecordAlertsRollsUpPerSource(t *testing.T) {
	st := openTestStore(t)
	t0 := time.Date(2026, 7, 21, 10, 0, 0, 0, time.UTC)

	// One source, three alerts, two distinct signatures, two distinct ports.
	err := st.RecordAlerts([]Alert{
		alert("203.0.113.7", 2403300, 22, 2, t0),
		alert("203.0.113.7", 2403300, 22, 2, t0.Add(time.Second)),
		alert("203.0.113.7", 2001219, 3389, 3, t0.Add(2*time.Second)),
	})
	if err != nil {
		t.Fatalf("record: %v", err)
	}

	src, err := st.GetSource("203.0.113.7")
	if err != nil {
		t.Fatalf("get source: %v", err)
	}
	if src.EventCount != 3 {
		t.Errorf("EventCount = %d, want 3", src.EventCount)
	}
	if src.SigCount != 2 {
		t.Errorf("SigCount = %d, want 2 (2403300 and 2001219)", src.SigCount)
	}
	if src.PortCount != 2 {
		t.Errorf("PortCount = %d, want 2 (22 and 3389)", src.PortCount)
	}
	if src.WorstSeverity != 2 {
		t.Errorf("WorstSeverity = %d, want 2 (severity counts down: 1 is worst)", src.WorstSeverity)
	}
	if !src.FirstSeen.Equal(t0) {
		t.Errorf("FirstSeen = %v, want %v", src.FirstSeen, t0)
	}
	if !src.LastSeen.Equal(t0.Add(2 * time.Second)) {
		t.Errorf("LastSeen = %v, want %v", src.LastSeen, t0.Add(2*time.Second))
	}
	if src.State != StateNew {
		t.Errorf("State = %q, want %q", src.State, StateNew)
	}
}

// A later batch must extend the rollup, not restart it — the incremental
// maintenance is only correct if repeated flushes accumulate.
func TestRecordAlertsAccumulatesAcrossBatches(t *testing.T) {
	st := openTestStore(t)
	t0 := time.Date(2026, 7, 21, 10, 0, 0, 0, time.UTC)

	for i := range 5 {
		if err := st.RecordAlerts([]Alert{
			alert("203.0.113.7", 2403300, 22, 3, t0.Add(time.Duration(i)*time.Minute)),
		}); err != nil {
			t.Fatalf("batch %d: %v", i, err)
		}
	}

	src, _ := st.GetSource("203.0.113.7")
	if src.EventCount != 5 {
		t.Errorf("EventCount = %d, want 5", src.EventCount)
	}
	if src.SigCount != 1 {
		t.Errorf("SigCount = %d, want 1 — the same signature five times is still one signature", src.SigCount)
	}
	if src.PortCount != 1 {
		t.Errorf("PortCount = %d, want 1", src.PortCount)
	}
}

// worst_severity is MIN() over what was seen, and a missing severity (0) must
// never win — otherwise one malformed alert erases a source's severity 1.
func TestWorstSeverityIgnoresMissingSeverity(t *testing.T) {
	st := openTestStore(t)
	t0 := time.Now().UTC()

	if err := st.RecordAlerts([]Alert{
		alert("203.0.113.9", 2001, 80, 3, t0),
		alert("203.0.113.9", 2002, 80, 1, t0.Add(time.Second)),
		alert("203.0.113.9", 2003, 80, 0, t0.Add(2*time.Second)), // no severity
	}); err != nil {
		t.Fatalf("record: %v", err)
	}
	src, _ := st.GetSource("203.0.113.9")
	if src.WorstSeverity != 1 {
		t.Errorf("WorstSeverity = %d, want 1", src.WorstSeverity)
	}
}

// A source that only ever produced severity-less alerts stays at 0, and the
// severity filter must not treat that as "severe".
func TestSeverityFilterExcludesUnknownSeverity(t *testing.T) {
	st := openTestStore(t)
	t0 := time.Now().UTC()
	if err := st.RecordAlerts([]Alert{
		alert("203.0.113.10", 3001, 80, 0, t0),
		alert("203.0.113.11", 3002, 80, 1, t0),
	}); err != nil {
		t.Fatalf("record: %v", err)
	}

	got, _, err := st.ListSources(SourceFilter{MaxSeverity: 3})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0].IP != "203.0.113.11" {
		t.Errorf("severity filter returned %v, want only 203.0.113.11", ips(got))
	}
}

// ICMP has no port, and the GPL ICMP rules were 10.6% of the observed flood.
// Recording port 0 as a "distinct port touched" would inflate every pinger.
func TestPortZeroIsNotCountedAsAPort(t *testing.T) {
	st := openTestStore(t)
	a := alert("203.0.113.12", 2100366, 0, 3, time.Now().UTC())
	a.Proto = "ICMP"
	if err := st.RecordAlerts([]Alert{a, a}); err != nil {
		t.Fatalf("record: %v", err)
	}
	src, _ := st.GetSource("203.0.113.12")
	if src.PortCount != 0 {
		t.Errorf("PortCount = %d, want 0 for ICMP", src.PortCount)
	}
	if src.EventCount != 2 {
		t.Errorf("EventCount = %d, want 2", src.EventCount)
	}
}

func TestSignatureRollup(t *testing.T) {
	st := openTestStore(t)
	t0 := time.Now().UTC()
	if err := st.RecordAlerts([]Alert{
		alert("203.0.113.1", 2403300, 22, 2, t0),
		alert("203.0.113.2", 2403300, 22, 2, t0),
		alert("203.0.113.2", 2403300, 22, 2, t0),
		alert("203.0.113.3", 2001219, 80, 3, t0),
	}); err != nil {
		t.Fatalf("record: %v", err)
	}

	sigs, err := st.TopSignatures(10)
	if err != nil {
		t.Fatalf("top signatures: %v", err)
	}
	if len(sigs) != 2 {
		t.Fatalf("got %d signatures, want 2", len(sigs))
	}
	if sigs[0].SID != 2403300 || sigs[0].Hits != 3 {
		t.Errorf("loudest = sid %d with %d hits, want 2403300 with 3", sigs[0].SID, sigs[0].Hits)
	}
	if sigs[0].SourceCount != 2 {
		t.Errorf("SourceCount = %d, want 2 distinct sources", sigs[0].SourceCount)
	}
	if sigs[0].Disposition != DispositionNotify {
		t.Errorf("Disposition = %q, want the default %q", sigs[0].Disposition, DispositionNotify)
	}
}

func TestSourceDetailListsSignaturesAndPorts(t *testing.T) {
	st := openTestStore(t)
	t0 := time.Now().UTC()
	if err := st.RecordAlerts([]Alert{
		alert("203.0.113.5", 2403300, 22, 2, t0),
		alert("203.0.113.5", 2403300, 22, 2, t0),
		alert("203.0.113.5", 2001219, 3389, 3, t0),
	}); err != nil {
		t.Fatalf("record: %v", err)
	}

	sigs, err := st.SignaturesForSource("203.0.113.5")
	if err != nil {
		t.Fatalf("signatures: %v", err)
	}
	if len(sigs) != 2 || sigs[0].SID != 2403300 || sigs[0].Hits != 2 {
		t.Errorf("signatures = %+v", sigs)
	}
	if sigs[0].Signature == "" {
		t.Error("signature text not joined from the signatures table")
	}

	ports, err := st.PortsForSource("203.0.113.5")
	if err != nil {
		t.Fatalf("ports: %v", err)
	}
	if len(ports) != 2 || ports[0].Port != 22 || ports[0].Hits != 2 {
		t.Errorf("ports = %+v", ports)
	}

	events, err := st.EventsForSource("203.0.113.5", 10)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	if len(events) != 3 {
		t.Errorf("got %d events, want 3", len(events))
	}
}

func TestListSourcesFilters(t *testing.T) {
	st := openTestStore(t)
	t0 := time.Date(2026, 7, 21, 10, 0, 0, 0, time.UTC)

	ro := alert("203.0.113.20", 2403300, 22, 1, t0)
	ro.Country, ro.CountryName, ro.ASN, ro.ASOrg = "RO", "Romania", 64500, "Example Telecom"
	us := alert("203.0.113.21", 2001219, 3389, 3, t0.Add(time.Hour))
	if err := st.RecordAlerts([]Alert{ro, us}); err != nil {
		t.Fatalf("record: %v", err)
	}

	cases := []struct {
		name   string
		filter SourceFilter
		want   []string
	}{
		{"all", SourceFilter{}, []string{"203.0.113.20", "203.0.113.21"}},
		{"country", SourceFilter{Country: "RO"}, []string{"203.0.113.20"}},
		{"asn", SourceFilter{ASN: 64500}, []string{"203.0.113.20"}},
		{"port", SourceFilter{Port: 3389}, []string{"203.0.113.21"}},
		{"sid", SourceFilter{SID: 2403300}, []string{"203.0.113.20"}},
		{"severity high only", SourceFilter{MaxSeverity: 1}, []string{"203.0.113.20"}},
		{"since", SourceFilter{Since: t0.Add(30 * time.Minute)}, []string{"203.0.113.21"}},
		{"state", SourceFilter{State: StateNew}, []string{"203.0.113.20", "203.0.113.21"}},
		{"query on as org", SourceFilter{Query: "Example"}, []string{"203.0.113.20"}},
		{"query on ip", SourceFilter{Query: "113.21"}, []string{"203.0.113.21"}},
		{"min events", SourceFilter{MinEvents: 2}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.filter.Sort = "ip"
			got, total, err := st.ListSources(tc.filter)
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			if int64(len(tc.want)) != total {
				t.Errorf("total = %d, want %d", total, len(tc.want))
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", ips(got), tc.want)
			}
			for i := range got {
				if got[i].IP != tc.want[i] {
					t.Errorf("got %v, want %v", ips(got), tc.want)
					break
				}
			}
		})
	}
}

func TestListSourcesSortAndPaginate(t *testing.T) {
	st := openTestStore(t)
	t0 := time.Date(2026, 7, 21, 10, 0, 0, 0, time.UTC)
	var batch []Alert
	for i := range 5 {
		// Later addresses are noisier and more recent.
		for range i + 1 {
			batch = append(batch, alert(ipN(i), 2000+i, 22, 3, t0.Add(time.Duration(i)*time.Minute)))
		}
	}
	if err := st.RecordAlerts(batch); err != nil {
		t.Fatalf("record: %v", err)
	}

	got, total, err := st.ListSources(SourceFilter{Sort: "events", Desc: true, Limit: 2})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 5 {
		t.Errorf("total = %d, want 5 (the count must ignore the limit)", total)
	}
	if len(got) != 2 || got[0].IP != ipN(4) || got[1].IP != ipN(3) {
		t.Errorf("page 1 = %v, want the two busiest", ips(got))
	}

	got, _, err = st.ListSources(SourceFilter{Sort: "events", Desc: true, Limit: 2, Offset: 2})
	if err != nil {
		t.Fatalf("list page 2: %v", err)
	}
	if len(got) != 2 || got[0].IP != ipN(2) {
		t.Errorf("page 2 = %v", ips(got))
	}

	// An unknown sort key falls back to the default rather than erroring or
	// silently ordering by something arbitrary.
	if _, ok := SortColumn("'; DROP TABLE sources; --"); ok {
		t.Error("SortColumn accepted an unknown key")
	}
	if _, _, err := st.ListSources(SourceFilter{Sort: "nonsense"}); err != nil {
		t.Errorf("unknown sort should fall back, got %v", err)
	}
}

func TestSetSourceState(t *testing.T) {
	st := openTestStore(t)
	if err := st.RecordAlerts([]Alert{alert("203.0.113.30", 2001, 22, 2, time.Now().UTC())}); err != nil {
		t.Fatalf("record: %v", err)
	}

	if err := st.SetSourceState("203.0.113.30", StateAcknowledged, "known scanner", "admin"); err != nil {
		t.Fatalf("set state: %v", err)
	}
	src, _ := st.GetSource("203.0.113.30")
	if src.State != StateAcknowledged || src.StateNote != "known scanner" || src.StateBy != "admin" {
		t.Errorf("state not recorded: %+v", src)
	}
	if src.StateAt.IsZero() {
		t.Error("StateAt not stamped")
	}

	if err := st.SetSourceState("203.0.113.30", "definitely-not-a-state", "", ""); err == nil {
		t.Error("expected an unknown state to be rejected")
	}
	if err := st.SetSourceState("198.51.100.1", StateBlocked, "", ""); err != ErrNotFound {
		t.Errorf("unknown source: got %v, want ErrNotFound", err)
	}
}

func TestGetSourceNotFound(t *testing.T) {
	st := openTestStore(t)
	if _, err := st.GetSource("198.51.100.99"); err != ErrNotFound {
		t.Errorf("got %v, want ErrNotFound", err)
	}
}

// Retention drops aged events, but a source someone triaged is a decision, and
// decisions outlive the events that prompted them.
func TestPruneKeepsTriagedSources(t *testing.T) {
	st := openTestStore(t)
	old := time.Now().UTC().Add(-30 * 24 * time.Hour)
	recent := time.Now().UTC()

	if err := st.RecordAlerts([]Alert{
		alert("203.0.113.40", 2001, 22, 2, old), // aged out, never triaged
		alert("203.0.113.41", 2002, 22, 2, old), // aged out, but blocked
		alert("203.0.113.42", 2003, 22, 2, recent),
	}); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := st.SetSourceState("203.0.113.41", StateBlocked, "confirmed in nftables", "admin"); err != nil {
		t.Fatalf("set state: %v", err)
	}

	res, err := st.Prune(time.Now().UTC().Add(-7*24*time.Hour), 0)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if res.Events != 2 {
		t.Errorf("pruned %d events, want 2", res.Events)
	}
	if res.Sources != 1 {
		t.Errorf("pruned %d sources, want 1", res.Sources)
	}

	if _, err := st.GetSource("203.0.113.40"); err != ErrNotFound {
		t.Error("an untriaged aged-out source should have been pruned")
	}
	if _, err := st.GetSource("203.0.113.41"); err != nil {
		t.Errorf("a blocked source must survive retention: %v", err)
	}
	if _, err := st.GetSource("203.0.113.42"); err != nil {
		t.Errorf("a recently active source must survive: %v", err)
	}

	// The pruned source's rollup rows must go with it.
	sigs, _ := st.SignaturesForSource("203.0.113.40")
	if len(sigs) != 0 {
		t.Errorf("orphaned source_signatures survived the prune: %+v", sigs)
	}
	// The surviving blocked source keeps its rollups even though its events went.
	if sigs, _ := st.SignaturesForSource("203.0.113.41"); len(sigs) != 1 {
		t.Errorf("a surviving source lost its rollup: %+v", sigs)
	}
}

// The max_events backstop exists because a flood can fill the disk well inside
// a 7-day window: 891 alerts in 4 minutes is 320k a day.
func TestPruneEnforcesMaxEvents(t *testing.T) {
	st := openTestStore(t)
	t0 := time.Now().UTC()
	var batch []Alert
	for i := range 50 {
		batch = append(batch, alert("203.0.113.50", 2001, 22, 3, t0.Add(time.Duration(i)*time.Second)))
	}
	if err := st.RecordAlerts(batch); err != nil {
		t.Fatalf("record: %v", err)
	}

	res, err := st.Prune(t0.Add(-24*time.Hour), 20)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if res.Events != 0 {
		t.Errorf("age-based prune removed %d events, want 0 — none are old", res.Events)
	}
	if res.OverCap != 30 {
		t.Errorf("cap prune removed %d, want 30", res.OverCap)
	}

	c, err := st.Summary()
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if c.Events != 20 {
		t.Errorf("%d events left, want 20", c.Events)
	}
	// The rollup is deliberately NOT rewound: sources is the durable ledger and
	// still reports every alert this source ever produced.
	src, _ := st.GetSource("203.0.113.50")
	if src.EventCount != 50 {
		t.Errorf("EventCount = %d, want 50 — the rollup survives event pruning", src.EventCount)
	}
}

// Pruning below the cap must be a no-op, not a delete of everything.
func TestPruneUnderCapDoesNothing(t *testing.T) {
	st := openTestStore(t)
	t0 := time.Now().UTC()
	if err := st.RecordAlerts([]Alert{alert("203.0.113.51", 2001, 22, 3, t0)}); err != nil {
		t.Fatalf("record: %v", err)
	}
	res, err := st.Prune(t0.Add(-24*time.Hour), 1000)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if res.Events != 0 || res.OverCap != 0 || res.Sources != 0 {
		t.Errorf("prune removed %+v, want nothing", res)
	}
	if c, _ := st.Summary(); c.Events != 1 {
		t.Errorf("%d events left, want 1", c.Events)
	}
}

func TestSummary(t *testing.T) {
	st := openTestStore(t)
	t0 := time.Date(2026, 7, 21, 10, 0, 0, 0, time.UTC)
	if err := st.RecordAlerts([]Alert{
		alert("203.0.113.60", 2001, 22, 2, t0),
		alert("203.0.113.61", 2002, 22, 2, t0.Add(time.Minute)),
	}); err != nil {
		t.Fatalf("record: %v", err)
	}
	_ = st.SetSourceState("203.0.113.60", StateBlocked, "", "admin")

	c, err := st.Summary()
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if c.Events != 2 || c.Sources != 2 || c.Signatures != 2 {
		t.Errorf("counts = %+v", c)
	}
	if c.NewSources != 1 || c.Blocked != 1 {
		t.Errorf("state counts = new %d blocked %d, want 1 and 1", c.NewSources, c.Blocked)
	}
	if !c.OldestEvent.Equal(t0) || !c.NewestEvent.Equal(t0.Add(time.Minute)) {
		t.Errorf("window = %v..%v", c.OldestEvent, c.NewestEvent)
	}
}

func TestSummaryOnEmptyDatabase(t *testing.T) {
	st := openTestStore(t)
	c, err := st.Summary()
	if err != nil {
		t.Fatalf("summary on an empty database: %v", err)
	}
	if c.Events != 0 || !c.OldestEvent.IsZero() {
		t.Errorf("counts = %+v", c)
	}
}

func TestEventsAfterFeedsTheLiveView(t *testing.T) {
	st := openTestStore(t)
	t0 := time.Now().UTC()
	if err := st.RecordAlerts([]Alert{alert("203.0.113.70", 2001, 22, 3, t0)}); err != nil {
		t.Fatalf("record: %v", err)
	}
	mark, err := st.MaxEventID()
	if err != nil {
		t.Fatalf("max id: %v", err)
	}

	if err := st.RecordAlerts([]Alert{alert("203.0.113.71", 2002, 22, 3, t0.Add(time.Second))}); err != nil {
		t.Fatalf("record: %v", err)
	}
	got, err := st.EventsAfter(mark, 100)
	if err != nil {
		t.Fatalf("events after: %v", err)
	}
	if len(got) != 1 || got[0].SrcIP != "203.0.113.71" {
		t.Errorf("got %+v, want only the new event", got)
	}
}

func TestFacets(t *testing.T) {
	st := openTestStore(t)
	t0 := time.Now().UTC()
	ro := alert("203.0.113.80", 2001, 22, 2, t0)
	ro.Country, ro.CountryName, ro.ASN, ro.ASOrg = "RO", "Romania", 64500, "Example Telecom"
	us := alert("203.0.113.81", 2002, 22, 2, t0)
	if err := st.RecordAlerts([]Alert{ro, us, us}); err != nil {
		t.Fatalf("record: %v", err)
	}

	countries, err := st.CountryFacets(10)
	if err != nil {
		t.Fatalf("country facets: %v", err)
	}
	if len(countries) != 2 {
		t.Errorf("countries = %+v", countries)
	}
	asns, err := st.ASNFacets(10)
	if err != nil {
		t.Fatalf("asn facets: %v", err)
	}
	if len(asns) != 2 {
		t.Errorf("asns = %+v", asns)
	}
	ports, err := st.PortFacets(10)
	if err != nil {
		t.Fatalf("port facets: %v", err)
	}
	if len(ports) != 1 || ports[0].Value != "22" || ports[0].Count != 2 {
		t.Errorf("ports = %+v, want port 22 across 2 sources", ports)
	}
}

func TestSettingsRoundTrip(t *testing.T) {
	st := openTestStore(t)
	if _, ok, err := st.GetSettings(); err != nil || ok {
		t.Fatalf("fresh database should have no settings row: ok=%v err=%v", ok, err)
	}

	if err := st.SaveIdentity("edge1", "0.0.0.0:8100"); err != nil {
		t.Fatalf("save identity: %v", err)
	}
	if err := st.SaveIngest("/var/log/suricata/eve.json", "/var/lib/meerkat/tail.state", 14, 500000); err != nil {
		t.Fatalf("save ingest: %v", err)
	}
	if err := st.SaveGeoIP("/var/lib/meerkat", "", "", "", true); err != nil {
		t.Fatalf("save geoip: %v", err)
	}

	got, ok, err := st.GetSettings()
	if err != nil || !ok {
		t.Fatalf("get settings: ok=%v err=%v", ok, err)
	}
	if got.RouterLabel != "edge1" || got.ListenAddr != "0.0.0.0:8100" {
		t.Errorf("identity = %+v", got)
	}
	if got.RetentionDays != 14 || got.MaxEvents != 500000 {
		t.Errorf("retention = %d days / %d events", got.RetentionDays, got.MaxEvents)
	}
	if !got.GeoIPAutoUpdate {
		t.Error("geoip autoupdate not saved")
	}
	// Each form owns its own columns: saving identity again must not blank the
	// ingest settings.
	if err := st.SaveIdentity("edge1-renamed", "127.0.0.1:8100"); err != nil {
		t.Fatalf("save identity again: %v", err)
	}
	got, _, _ = st.GetSettings()
	if got.EvePath == "" || got.RetentionDays != 14 {
		t.Errorf("identity save clobbered ingest settings: %+v", got)
	}
}

func TestAuditAndActionLedger(t *testing.T) {
	st := openTestStore(t)
	if err := st.InsertAudit("admin", AuditLogin, "signed in"); err != nil {
		t.Fatalf("audit: %v", err)
	}
	entries, err := st.ListAudit(10, 0)
	if err != nil || len(entries) != 1 {
		t.Fatalf("list audit: %d entries, err %v", len(entries), err)
	}
	if entries[0].Actor != "admin" || entries[0].Kind != AuditLogin {
		t.Errorf("entry = %+v", entries[0])
	}

	if err := st.RecordAction(Action{
		Actor: "admin", Action: ActionBlock, Target: "203.0.113.90",
		Reason: "scanning", Result: "applied to the kernel", OK: true,
	}); err != nil {
		t.Fatalf("record action: %v", err)
	}
	actions, err := st.ActionsForTarget("203.0.113.90", 10)
	if err != nil || len(actions) != 1 {
		t.Fatalf("actions: %d, err %v", len(actions), err)
	}
	if !actions[0].OK || actions[0].Action != ActionBlock {
		t.Errorf("action = %+v", actions[0])
	}
}

func TestSetDisposition(t *testing.T) {
	st := openTestStore(t)
	if err := st.RecordAlerts([]Alert{alert("203.0.113.95", 2403300, 22, 2, time.Now().UTC())}); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := st.SetDisposition(2403300, DispositionMute); err != nil {
		t.Fatalf("set disposition: %v", err)
	}
	sigs, _ := st.TopSignatures(1)
	if sigs[0].Disposition != DispositionMute {
		t.Errorf("disposition = %q", sigs[0].Disposition)
	}
	if err := st.SetDisposition(2403300, "shout"); err == nil {
		t.Error("expected an unknown disposition to be rejected")
	}
	if err := st.SetDisposition(999999, DispositionMute); err != ErrNotFound {
		t.Errorf("unknown sid: got %v, want ErrNotFound", err)
	}
}

func TestRecordAlertsEmptyBatchIsANoOp(t *testing.T) {
	st := openTestStore(t)
	if err := st.RecordAlerts(nil); err != nil {
		t.Fatalf("empty batch: %v", err)
	}
}

func ips(sources []Source) []string {
	out := make([]string, len(sources))
	for i, s := range sources {
		out[i] = s.IP
	}
	return out
}

func ipN(i int) string { return fmt.Sprintf("203.0.113.%d", 100+i) }

func TestHourlyActivity(t *testing.T) {
	st := openTestStore(t)
	now := time.Now().UTC()
	if err := st.RecordAlerts([]Alert{
		alert("203.0.113.1", 2001, 22, 2, now.Add(-90*time.Minute)),
		alert("203.0.113.2", 2001, 22, 2, now.Add(-30*time.Minute)),
		alert("203.0.113.3", 2001, 22, 2, now.Add(-20*time.Minute)),
		alert("203.0.113.4", 2001, 22, 2, now.Add(-300*time.Hour)), // outside the window
	}); err != nil {
		t.Fatalf("record: %v", err)
	}

	buckets, err := st.HourlyActivity(24)
	if err != nil {
		t.Fatalf("hourly: %v", err)
	}
	if len(buckets) != 24 {
		t.Fatalf("got %d buckets, want 24 — empty hours must be present so the chart has no gaps", len(buckets))
	}
	var total int64
	for _, b := range buckets {
		total += b.Count
	}
	if total != 3 {
		t.Errorf("counted %d alerts in the window, want 3 (the fourth is outside it)", total)
	}
	// Oldest first, and every bucket an hour apart.
	for i := 1; i < len(buckets); i++ {
		if !buckets[i].Start.After(buckets[i-1].Start) {
			t.Fatalf("buckets are not in ascending order at %d", i)
		}
		if d := buckets[i].Start.Sub(buckets[i-1].Start); d != time.Hour {
			t.Fatalf("bucket %d is %v after the previous, want 1h", i, d)
		}
	}
	// Assert placement by hour rather than "the newest bucket": an alert 30
	// minutes old lands in the previous hour whenever the clock has just ticked
	// over, so the naive version of this passes or fails depending on when the
	// suite runs.
	want := map[string]int64{}
	for _, at := range []time.Time{now.Add(-90 * time.Minute), now.Add(-30 * time.Minute), now.Add(-20 * time.Minute)} {
		want[FormatTime(at.Truncate(time.Hour))[:13]]++
	}
	for _, b := range buckets {
		key := FormatTime(b.Start)[:13]
		if b.Count != want[key] {
			t.Errorf("bucket %s has %d, want %d", key, b.Count, want[key])
		}
	}
}

func TestTopSources(t *testing.T) {
	st := openTestStore(t)
	now := time.Now().UTC()
	var batch []Alert
	for i := range 4 {
		for range i + 1 {
			batch = append(batch, alert(ipN(i), 2001, 22, 2, now))
		}
	}
	if err := st.RecordAlerts(batch); err != nil {
		t.Fatalf("record: %v", err)
	}
	top, err := st.TopSources(2)
	if err != nil {
		t.Fatalf("top sources: %v", err)
	}
	if len(top) != 2 || top[0].IP != ipN(3) || top[1].IP != ipN(2) {
		t.Errorf("got %v, want the two busiest", ips(top))
	}
}

// The three sister projects share one look, and green is its accent. A database
// still carrying the old 'ocean' default should move across on upgrade — that
// value was never a choice, just a column default.
func TestDefaultAccentIsGreen(t *testing.T) {
	st := openTestStore(t)
	if err := st.SaveIdentity("edge1", "0.0.0.0:8100"); err != nil {
		t.Fatalf("identity: %v", err)
	}
	got, _, err := st.GetSettings()
	if err != nil {
		t.Fatalf("get settings: %v", err)
	}
	if got.ThemeAccent != "green" {
		t.Errorf("fresh install accent = %q, want green", got.ThemeAccent)
	}
}
