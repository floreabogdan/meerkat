package web

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/floreabogdan/meerkat/internal/store"
)

func testServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "meerkat.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	if err := st.SaveIdentity("edge1", "0.0.0.0:8100"); err != nil {
		t.Fatalf("save identity: %v", err)
	}
	hash, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if _, err := st.CreateUser("admin", hash); err != nil {
		t.Fatalf("create user: %v", err)
	}

	srv := New(Config{
		Store:      st,
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		ListenAddr: "127.0.0.1:8100",
		DataDir:    t.TempDir(),
	})
	return srv, st
}

// login performs a real login and returns the session cookie, so page tests
// exercise the same path a browser does.
func login(t *testing.T, srv *Server) *http.Cookie {
	t.Helper()
	form := url.Values{"username": {"admin"}, "password": {"correct horse battery"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login returned %d, want 303", rec.Code)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName && c.Value != "" {
			return c
		}
	}
	t.Fatal("login set no session cookie")
	return nil
}

func get(t *testing.T, srv *Server, cookie *http.Cookie, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func post(t *testing.T, srv *Server, cookie *http.Cookie, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func seed(t *testing.T, st *store.Store) {
	t.Helper()
	t0 := time.Now().UTC().Add(-time.Hour)
	mk := func(ip string, sid, port, sev int, at time.Time) store.Alert {
		return store.Alert{
			Ts: at, SrcIP: ip, DestIP: "192.0.2.1", DestPort: port, Proto: "TCP",
			SID: sid, Sig: "ET SCAN Potential SSH Scan", Category: "Attempted Information Leak",
			Severity: sev, Action: "allowed",
			Country: "RO", CountryName: "Romania", ASN: 64500, ASOrg: "Example Telecom & Co", City: "Example City",
		}
	}
	batch := []store.Alert{
		mk("198.51.100.7", 2001219, 22, 2, t0),
		mk("198.51.100.7", 2001219, 22, 2, t0.Add(time.Minute)),
		mk("198.51.100.7", 2403300, 3389, 1, t0.Add(2*time.Minute)),
		mk("203.0.113.49", 2001219, 22, 3, t0.Add(3*time.Minute)),
	}
	batch[3].Country, batch[3].CountryName, batch[3].ASN, batch[3].ASOrg = "NL", "Netherlands", 64501, "Example Hosting"
	local := mk("192.168.1.50", 2001219, 22, 3, t0.Add(4*time.Minute))
	local.IsLocal, local.Country, local.ASN = true, "", 0
	batch = append(batch, local)

	if err := st.RecordAlerts(batch); err != nil {
		t.Fatalf("seed: %v", err)
	}
}

// seedMany records n distinct sources, enough that paging actually engages —
// the pager correctly hides itself when everything fits on one page.
func seedMany(t *testing.T, st *store.Store, n int) {
	t.Helper()
	t0 := time.Now().UTC().Add(-time.Hour)
	batch := make([]store.Alert, 0, n)
	for i := range n {
		batch = append(batch, store.Alert{
			Ts:    t0.Add(time.Duration(i) * time.Second),
			SrcIP: fmt.Sprintf("198.51.100.%d", i%250+1), DestIP: "192.0.2.1", DestPort: 22,
			Proto: "TCP", SID: 2001219, Sig: "ET SCAN Potential SSH Scan", Severity: 2,
			Action: "allowed", Country: "RO", CountryName: "Romania", ASN: 64500, ASOrg: "Example Telecom & Co",
		})
	}
	if err := st.RecordAlerts(batch); err != nil {
		t.Fatalf("seed many: %v", err)
	}
}

// Every authenticated page must render. A template is only compiled when it is
// executed, so without this a typo in any of them ships.
func TestEveryPageRenders(t *testing.T) {
	srv, st := testServer(t)
	seed(t, st)
	cookie := login(t, srv)

	pages := []string{
		"/",
		"/sources",
		"/sources?q=45.155&country=RO&asn=64500&port=22&severity=2&state=new&window=24h&min_events=1&sort=events&dir=asc",
		"/sources?sid=2001219",
		"/sources?page=2",
		"/signatures",
		"/sources/198.51.100.7",
		"/sources/192.168.1.50",
		"/live",
		"/timeline",
		"/settings",
		"/settings?tab=ingest",
		"/settings?tab=geoip",
		"/settings?tab=blocking",
		"/settings?tab=threats",
		"/settings?tab=access",
		"/settings?tab=theme",
		"/profile",
	}
	for _, p := range pages {
		t.Run(p, func(t *testing.T) {
			rec := get(t, srv, cookie, p)
			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s = %d\n%s", p, rec.Code, rec.Body.String())
			}
			body := rec.Body.String()
			if !strings.Contains(body, "</html>") {
				t.Errorf("GET %s produced a truncated page — a template failed mid-render", p)
			}
			// html/template writes what it has before erroring, so a partial
			// page is the signature of a bad field reference.
			if strings.Contains(body, "<no value>") {
				t.Errorf("GET %s rendered a missing value", p)
			}
		})
	}
}

// An empty database is the state on a fresh install, and every page has to cope
// with it — that is exactly when someone is looking.
func TestPagesRenderWithNoData(t *testing.T) {
	srv, _ := testServer(t)
	cookie := login(t, srv)
	for _, p := range []string{"/", "/sources", "/signatures", "/live", "/timeline", "/settings", "/profile"} {
		rec := get(t, srv, cookie, p)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s on an empty database = %d", p, rec.Code)
		}
	}
}

func TestAuthenticationIsRequired(t *testing.T) {
	srv, st := testServer(t)
	seed(t, st)

	for _, p := range []string{"/", "/sources", "/sources/198.51.100.7", "/live", "/timeline", "/settings", "/profile", "/api/status", "/api/events"} {
		rec := get(t, srv, nil, p)
		if rec.Code != http.StatusSeeOther {
			t.Errorf("GET %s without a session = %d, want a redirect to /login", p, rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "/login" {
			t.Errorf("GET %s redirected to %q", p, loc)
		}
	}
}

func TestBadLoginIsRejected(t *testing.T) {
	srv, _ := testServer(t)
	form := url.Values{"username": {"admin"}, "password": {"wrong"}}
	rec := post(t, srv, nil, "/login", form)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login?error=1" {
		t.Errorf("bad login = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName && c.Value != "" {
			t.Error("a failed login set a session cookie")
		}
	}
}

// The sources list is the home page. Filtering it is the main interaction, so
// each control has to actually reach the query.
func TestSourcesFiltering(t *testing.T) {
	srv, st := testServer(t)
	seed(t, st)
	cookie := login(t, srv)

	cases := []struct {
		query      string
		wantShown  []string
		wantHidden []string
	}{
		{"/sources", []string{"198.51.100.7", "203.0.113.49", "192.168.1.50"}, nil},
		{"/sources?country=NL", []string{"203.0.113.49"}, []string{"198.51.100.7"}},
		{"/sources?asn=64500", []string{"198.51.100.7"}, []string{"203.0.113.49"}},
		{"/sources?port=3389", []string{"198.51.100.7"}, []string{"203.0.113.49"}},
		{"/sources?sid=2403300", []string{"198.51.100.7"}, []string{"203.0.113.49"}},
		{"/sources?severity=1", []string{"198.51.100.7"}, []string{"203.0.113.49"}},
		{"/sources?q=Telecom", []string{"198.51.100.7"}, []string{"203.0.113.49"}},
		{"/sources?min_events=3", []string{"198.51.100.7"}, []string{"203.0.113.49"}},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			body := get(t, srv, cookie, tc.query).Body.String()
			// Match the row link, not the raw address: the filter bar echoes
			// values back, so a bare address can appear without a matching row.
			for _, ip := range tc.wantShown {
				if !strings.Contains(body, `/sources/`+ip) {
					t.Errorf("%s: expected a row for %s", tc.query, ip)
				}
			}
			for _, ip := range tc.wantHidden {
				if strings.Contains(body, `/sources/`+ip) {
					t.Errorf("%s: did not expect a row for %s", tc.query, ip)
				}
			}
		})
	}
}

// A filter value that cannot be parsed must empty the table, not 500 the page
// or silently return everything as if no filter had been asked for.
func TestGarbageFilterValuesAreSafe(t *testing.T) {
	srv, st := testServer(t)
	seed(t, st)
	cookie := login(t, srv)

	for _, q := range []string{
		"/sources?asn=not-a-number",
		"/sources?port=99999999999999999999",
		"/sources?severity=99",
		"/sources?state=%27+OR+1%3D1+--",
		"/sources?sort=%27%3B+DROP+TABLE+sources%3B+--",
		"/sources?country=%27%3B+DROP+TABLE+sources%3B+--",
		"/sources?window=nonsense",
		"/sources?page=-5",
		"/sources?min_events=abc",
	} {
		rec := get(t, srv, cookie, q)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", q, rec.Code)
		}
	}
	// The injection attempt must not have taken anything with it.
	if _, err := st.GetSource("198.51.100.7"); err != nil {
		t.Fatalf("data disappeared after hostile query strings: %v", err)
	}
}

func TestSourceDetail(t *testing.T) {
	srv, st := testServer(t)
	seed(t, st)
	cookie := login(t, srv)

	body := get(t, srv, cookie, "/sources/198.51.100.7").Body.String()
	for _, want := range []string{
		"198.51.100.7",
		"2001219",                    // a signature it tripped
		"2403300",                    // and the other
		"3389",                       // a port it touched
		"Example Telecom &amp; Co",   // enrichment, escaped
		"ET SCAN Potential SSH Scan", // the signature text
	} {
		if !strings.Contains(body, want) {
			t.Errorf("source detail is missing %q", want)
		}
	}
}

// The detail page for a private source has to say so: it is one of ours, and
// blocking it at the edge would be a mistake.
func TestLocalSourceIsCalledOut(t *testing.T) {
	srv, st := testServer(t)
	seed(t, st)
	cookie := login(t, srv)

	body := get(t, srv, cookie, "/sources/192.168.1.50").Body.String()
	if !strings.Contains(body, "one of ours") {
		t.Error("a private source should be flagged as internal on its detail page")
	}
}

func TestUnknownSourceIs404(t *testing.T) {
	srv, _ := testServer(t)
	cookie := login(t, srv)
	if rec := get(t, srv, cookie, "/sources/198.51.100.99"); rec.Code != http.StatusNotFound {
		t.Errorf("unknown source = %d, want 404", rec.Code)
	}
	// A path segment that is not an address at all must be rejected before it
	// ever reaches the database.
	if rec := get(t, srv, cookie, "/sources/not-an-address"); rec.Code != http.StatusNotFound {
		t.Errorf("non-address path = %d, want 404", rec.Code)
	}
}

func TestLiveEventsAPI(t *testing.T) {
	srv, st := testServer(t)
	seed(t, st)
	cookie := login(t, srv)

	rec := get(t, srv, cookie, "/api/events?after=0")
	if rec.Code != http.StatusOK {
		t.Fatalf("api/events = %d", rec.Code)
	}
	var body struct {
		Events []struct {
			ID        int64  `json:"id"`
			SrcIP     string `json:"srcIp"`
			Signature string `json:"signature"`
			Severity  int    `json:"severity"`
		} `json:"events"`
		Cursor int64 `json:"cursor"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v — %s", err, rec.Body.String())
	}
	if len(body.Events) != 5 {
		t.Errorf("got %d events, want 5", len(body.Events))
	}
	if body.Cursor == 0 {
		t.Error("cursor not advanced")
	}

	// Polling again from the cursor must return nothing, or the live view would
	// re-add every row on every tick.
	rec = get(t, srv, cookie, "/api/events?after="+itoa64(body.Cursor))
	var second struct {
		Events []json.RawMessage `json:"events"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &second)
	if len(second.Events) != 0 {
		t.Errorf("re-polling from the cursor returned %d events, want 0", len(second.Events))
	}
}

func TestStatusAPI(t *testing.T) {
	srv, st := testServer(t)
	seed(t, st)
	cookie := login(t, srv)

	rec := get(t, srv, cookie, "/api/status")
	if rec.Code != http.StatusOK {
		t.Fatalf("api/status = %d", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// No ingester was wired up in this test server, and the status must say so
	// rather than implying a healthy reader.
	if body["ingestRunning"] != false {
		t.Errorf("ingestRunning = %v, want false", body["ingestRunning"])
	}
	if body["events"].(float64) != 5 {
		t.Errorf("events = %v, want 5", body["events"])
	}
}

func TestSettingsRoundTripThroughTheForms(t *testing.T) {
	srv, st := testServer(t)
	cookie := login(t, srv)

	if rec := post(t, srv, cookie, "/settings/ingest", url.Values{
		"eve_path": {"/var/log/suricata/eve.json"}, "state_path": {"/var/lib/meerkat/tail.state"},
		"retention_days": {"14"}, "max_events": {"500000"},
	}); rec.Code != http.StatusSeeOther {
		t.Fatalf("save ingest = %d", rec.Code)
	}
	got, _, _ := st.GetSettings()
	if got.RetentionDays != 14 || got.MaxEvents != 500000 {
		t.Errorf("ingest settings = %+v", got)
	}

	if rec := post(t, srv, cookie, "/settings/nftably", url.Values{
		"nftably_url": {"http://127.0.0.1:8099/"}, "nftably_token": {"s3cret"},
	}); rec.Code != http.StatusSeeOther {
		t.Fatalf("save nftably = %d", rec.Code)
	}
	got, _, _ = st.GetSettings()
	if got.NftablyURL != "http://127.0.0.1:8099" {
		t.Errorf("trailing slash not trimmed: %q", got.NftablyURL)
	}
	if got.NftablyToken != "s3cret" {
		t.Errorf("token = %q", got.NftablyToken)
	}
}

// The token field is a password input that never shows its value back, so
// re-saving the URL with the field left blank must keep the stored token
// rather than silently wiping it and breaking blocking.
func TestBlankNftablyTokenKeepsTheStoredOne(t *testing.T) {
	srv, st := testServer(t)
	cookie := login(t, srv)

	post(t, srv, cookie, "/settings/nftably", url.Values{
		"nftably_url": {"http://127.0.0.1:8099"}, "nftably_token": {"keepme"},
	})
	post(t, srv, cookie, "/settings/nftably", url.Values{
		"nftably_url": {"http://10.0.0.1:8099"}, "nftably_token": {""},
	})

	got, _, _ := st.GetSettings()
	if got.NftablyToken != "keepme" {
		t.Errorf("token = %q, want it preserved", got.NftablyToken)
	}
	if got.NftablyURL != "http://10.0.0.1:8099" {
		t.Errorf("url = %q, want it updated", got.NftablyURL)
	}
}

// Out-of-range retention must be clamped, not stored: a settings form should
// never be able to configure -3 days.
func TestRetentionIsClamped(t *testing.T) {
	srv, st := testServer(t)
	cookie := login(t, srv)

	for _, tc := range []struct{ in, want int }{{-3, 1}, {0, 1}, {99999, 3650}, {30, 30}} {
		post(t, srv, cookie, "/settings/ingest", url.Values{
			"eve_path": {"/x"}, "retention_days": {itoa(tc.in)}, "max_events": {"100000"},
		})
		got, _, _ := st.GetSettings()
		if got.RetentionDays != tc.want {
			t.Errorf("retention %d stored as %d, want %d", tc.in, got.RetentionDays, tc.want)
		}
	}
}

// The threat-map form is the one that can leak customer addresses if it saves a
// half-configured state, so it refuses rather than publishes.
func TestThreatMapSettings(t *testing.T) {
	srv, st := testServer(t)
	cookie := login(t, srv)

	full := url.Values{
		"enabled": {"on"}, "threats_url": {"https://threats.example.net/api/threats/ingest"},
		"threats_token": {"tok"}, "site_name": {"Example Site"}, "site_country": {"ro"},
		"site_lat": {"44.8565"}, "site_lng": {"24.8692"},
		"home_nets": {"192.0.2.0/24\n10.0.0.0/8"},
	}
	if rec := post(t, srv, cookie, "/settings/threats", full); rec.Code != http.StatusSeeOther {
		t.Fatalf("save = %d", rec.Code)
	}
	got, _, _ := st.GetSettings()
	if !got.ThreatsEnabled || got.SiteName != "Example Site" || got.ThreatsToken != "tok" {
		t.Errorf("settings = %+v", got)
	}
	if got.SiteCountry != "RO" {
		t.Errorf("country should be upper-cased: %q", got.SiteCountry)
	}
	if got.SiteLat == 0 || got.SiteLng == 0 {
		t.Errorf("coordinates = %v,%v", got.SiteLat, got.SiteLng)
	}

	// Enabling without coordinates must be refused: every arc would land at 0,0.
	noCoords := url.Values{}
	for k, v := range full {
		noCoords[k] = v
	}
	noCoords.Set("site_lat", "0")
	noCoords.Set("site_lng", "0")
	rec := post(t, srv, cookie, "/settings/threats", noCoords)
	if !strings.Contains(rec.Header().Get("Location"), "err=") {
		t.Error("enabling without coordinates should be refused")
	}

	// A malformed exclusion list must not be stored — it is what keeps customer
	// addresses off a public page.
	badNets := url.Values{}
	for k, v := range full {
		badNets[k] = v
	}
	badNets.Set("home_nets", "not-a-cidr")
	rec = post(t, srv, cookie, "/settings/threats", badNets)
	if !strings.Contains(rec.Header().Get("Location"), "err=") {
		t.Error("a malformed home-net list should be refused")
	}
	got, _, _ = st.GetSettings()
	if strings.Contains(got.HomeNets, "not-a-cidr") {
		t.Errorf("a malformed home-net list was stored: %q", got.HomeNets)
	}

	// A blank token keeps the stored one, like the nftably form.
	keep := url.Values{}
	for k, v := range full {
		keep[k] = v
	}
	keep.Set("threats_token", "")
	keep.Set("site_name", "Example Site")
	post(t, srv, cookie, "/settings/threats", keep)
	got, _, _ = st.GetSettings()
	if got.ThreatsToken != "tok" {
		t.Errorf("token = %q, want it preserved", got.ThreatsToken)
	}
	if got.SiteName != "Example Site" {
		t.Errorf("site name = %q, want it updated", got.SiteName)
	}
}

// The cursor is the shipper's bookmark; a settings save must never move it, or
// history is silently re-published or skipped.
func TestSavingThreatSettingsDoesNotMoveTheCursor(t *testing.T) {
	srv, st := testServer(t)
	cookie := login(t, srv)
	if err := st.SetThreatsCursor(4242); err != nil {
		t.Fatalf("cursor: %v", err)
	}
	post(t, srv, cookie, "/settings/threats", url.Values{
		"enabled": {"on"}, "threats_url": {"https://threats.example.net/api/threats/ingest"},
		"threats_token": {"tok"}, "site_name": {"Example Site"},
		"site_lat": {"44.86"}, "site_lng": {"24.87"}, "home_nets": {"10.0.0.0/8"},
	})
	got, _, _ := st.GetSettings()
	if got.ThreatsCursor != 4242 {
		t.Errorf("cursor moved to %d on a settings save", got.ThreatsCursor)
	}
}

func TestAccessWhitelistRejectsGarbage(t *testing.T) {
	srv, st := testServer(t)
	cookie := login(t, srv)

	rec := post(t, srv, cookie, "/settings/access", url.Values{"access_whitelist": {"not-an-ip"}})
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "err=") {
		t.Errorf("a malformed allow-list should be rejected, got %q", loc)
	}
	got, _, _ := st.GetSettings()
	if got.AccessWhitelist != "" {
		t.Errorf("a malformed allow-list was stored: %q", got.AccessWhitelist)
	}
}

// The allow-list is the outer boundary: a client outside it gets the connection
// closed, not a login page.
func TestAccessWhitelistGatesRequests(t *testing.T) {
	srv, st := testServer(t)
	if err := st.SaveAccessWhitelist("10.0.0.0/8"); err != nil {
		t.Fatalf("save whitelist: %v", err)
	}
	srv.reloadAccess()

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.RemoteAddr = "203.0.113.9:5555"
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("an off-list client got %d, want 403", rec.Code)
	}

	// Loopback is always allowed, so an SSH tunnel can never be locked out.
	req = httptest.NewRequest(http.MethodGet, "/login", nil)
	req.RemoteAddr = "127.0.0.1:5555"
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("loopback got %d, want 200 — it must never be locked out", rec.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	srv, _ := testServer(t)
	rec := get(t, srv, nil, "/login")
	for header, want := range map[string]string{
		"X-Frame-Options":        "DENY",
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "same-origin",
	} {
		if got := rec.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe-inline") {
		t.Errorf("CSP allows inline script: %q", csp)
	}
}

// The CSP forbids inline script, so an inline <script> block in any template
// would render a silently broken page in the browser and pass every server-side
// test. Catch it here instead.
func TestNoInlineScriptInTemplates(t *testing.T) {
	srv, st := testServer(t)
	seed(t, st)
	cookie := login(t, srv)

	for _, p := range []string{"/", "/sources", "/signatures", "/sources/198.51.100.7", "/live", "/timeline", "/settings", "/profile", "/login"} {
		body := get(t, srv, cookie, p).Body.String()
		// A <script> with no src= is an inline block.
		for _, tag := range scriptTags(body) {
			if !strings.Contains(tag, "src=") {
				t.Errorf("%s contains an inline <script>, which the CSP blocks: %s", p, tag)
			}
		}
	}
}

// anchorHrefs pulls every href value out of a rendered page.
func anchorHrefs(body string) []string {
	var out []string
	rest := body
	for {
		i := strings.Index(rest, `href="`)
		if i < 0 {
			return out
		}
		rest = rest[i+len(`href="`):]
		j := strings.Index(rest, `"`)
		if j < 0 {
			return out
		}
		out = append(out, rest[:j])
		rest = rest[j:]
	}
}

// The CSP sets style-src 'self' with no 'unsafe-inline', so a style="…"
// attribute is silently dropped by the browser. That is a nasty failure mode:
// the server renders exactly what the template says, every server-side test
// passes, and the page is wrong only in a real browser. It bit the signature
// bars and the activity sparkline, which both rendered full-size because their
// inline widths were discarded. Proportional graphics use <progress value max>
// or SVG geometry attributes instead.
func TestNoInlineStyleInTemplates(t *testing.T) {
	srv, st := testServer(t)
	seed(t, st)
	cookie := login(t, srv)

	for _, p := range []string{"/", "/sources", "/sources/198.51.100.7", "/live", "/timeline", "/settings", "/profile", "/login"} {
		body := get(t, srv, cookie, p).Body.String()
		if i := strings.Index(body, "style=\""); i >= 0 {
			end := min(i+80, len(body))
			t.Errorf("%s contains an inline style attribute, which the CSP drops: %s", p, body[i:end])
		}
	}
}

func scriptTags(body string) []string {
	var out []string
	rest := body
	for {
		i := strings.Index(rest, "<script")
		if i < 0 {
			return out
		}
		rest = rest[i:]
		j := strings.Index(rest, ">")
		if j < 0 {
			return out
		}
		out = append(out, rest[:j+1])
		rest = rest[j+1:]
	}
}

// A cross-origin POST must be refused even with a valid cookie.
func TestCrossOriginWriteRejected(t *testing.T) {
	srv, _ := testServer(t)
	cookie := login(t, srv)

	req := httptest.NewRequest(http.MethodPost, "/settings/identity", strings.NewReader("label=evil"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.example")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("cross-origin POST = %d, want 403", rec.Code)
	}
}

// The theme toggle redirects back to where the operator was, and that Referer
// is attacker-influencable — it must never become an open redirect.
func TestThemeToggleDoesNotOpenRedirect(t *testing.T) {
	srv, _ := testServer(t)
	cookie := login(t, srv)

	for _, referer := range []string{"https://evil.example/x", "//evil.example/x", ""} {
		req := httptest.NewRequest(http.MethodPost, "/settings/theme/mode", nil)
		req.Header.Set("Referer", referer)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if loc := rec.Header().Get("Location"); loc != "/" {
			t.Errorf("Referer %q redirected to %q, want /", referer, loc)
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/settings/theme/mode", nil)
	req.Header.Set("Referer", "/sources/198.51.100.7")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if loc := rec.Header().Get("Location"); loc != "/sources/198.51.100.7" {
		t.Errorf("a local Referer should be honoured, got %q", loc)
	}
}

func TestPasswordChange(t *testing.T) {
	srv, _ := testServer(t)
	cookie := login(t, srv)

	// Wrong current password is refused.
	rec := post(t, srv, cookie, "/profile/password", url.Values{
		"current": {"nope"}, "password": {"a-new-long-password"}, "confirm": {"a-new-long-password"},
	})
	if !strings.Contains(rec.Header().Get("Location"), "err=") {
		t.Error("a wrong current password should be refused")
	}

	// Mismatched confirmation is refused.
	rec = post(t, srv, cookie, "/profile/password", url.Values{
		"current": {"correct horse battery"}, "password": {"a-new-long-password"}, "confirm": {"different"},
	})
	if !strings.Contains(rec.Header().Get("Location"), "err=") {
		t.Error("a mismatched confirmation should be refused")
	}

	// Too short is refused.
	rec = post(t, srv, cookie, "/profile/password", url.Values{
		"current": {"correct horse battery"}, "password": {"short"}, "confirm": {"short"},
	})
	if !strings.Contains(rec.Header().Get("Location"), "err=") {
		t.Error("a short password should be refused")
	}

	// A good change succeeds and the old password stops working.
	rec = post(t, srv, cookie, "/profile/password", url.Values{
		"current": {"correct horse battery"}, "password": {"a-new-long-password"}, "confirm": {"a-new-long-password"},
	})
	if !strings.Contains(rec.Header().Get("Location"), "saved=") {
		t.Fatalf("password change failed: %q", rec.Header().Get("Location"))
	}
	old := post(t, srv, nil, "/login", url.Values{"username": {"admin"}, "password": {"correct horse battery"}})
	if !strings.Contains(old.Header().Get("Location"), "error") {
		t.Error("the old password still works after a change")
	}
}

// Sorting is server-side, so each header's link has to carry a key the store
// actually accepts — and must not carry the page number with it.
func TestSortLinksAreValidAndDropThePage(t *testing.T) {
	srv, st := testServer(t)
	seed(t, st)
	cookie := login(t, srv)

	// Page one deliberately: the headers only exist when there are rows.
	body := get(t, srv, cookie, "/sources?country=RO&page=1&sort=events&dir=desc").Body.String()
	for _, c := range tableColumns {
		if c.Key == "" {
			continue
		}
		if _, ok := store.SortColumn(c.Key); !ok {
			t.Errorf("column %q is not a sort key the store accepts", c.Key)
		}
		if !strings.Contains(body, "sort="+c.Key) {
			t.Errorf("no sort link for %q", c.Key)
		}
	}
	for _, tag := range anchorHrefs(body) {
		if strings.Contains(tag, "sort=") && strings.Contains(tag, "page=") {
			t.Errorf("a sort link carried the page number; re-sorting should return to page one: %s", tag)
		}
	}
	// The filter has to survive a re-sort, or sorting silently widens the view.
	if !strings.Contains(body, "country=RO&amp;sort=") {
		t.Error("a sort link dropped the active country filter")
	}
}

// Paging must preserve every filter, for the same reason.
func TestPagingPreservesFilters(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/sources?country=RO&severity=2&sort=events", nil)
	got := pagedURL(req, sourcesPath, 2, defaultPageSize)
	for _, want := range []string{"country=RO", "severity=2", "sort=events", "page=2"} {
		if !strings.Contains(got, want) {
			t.Errorf("pagedURL dropped %q: %s", want, got)
		}
	}
	// Page one and the default size are the bare URL, not "?page=1&size=100".
	if bare := pagedURL(req, sourcesPath, 1, defaultPageSize); strings.Contains(bare, "page=") || strings.Contains(bare, "size=") {
		t.Errorf("page one at the default size should carry neither parameter: %s", bare)
	}
	// Changing the page size returns to page one.
	if sized := pagedURL(req, sourcesPath, 1, 25); !strings.Contains(sized, "size=25") || strings.Contains(sized, "page=") {
		t.Errorf("size change should reset to page one: %s", sized)
	}
}

func TestPageWindowElidesLongRuns(t *testing.T) {
	cases := []struct {
		current, pages int
		want           []int
	}{
		{1, 1, []int{1}},
		{3, 5, []int{1, 2, 3, 4, 5}},
		{1, 20, []int{1, 2, 0, 20}},
		{10, 20, []int{1, 0, 9, 10, 11, 0, 20}},
		{20, 20, []int{1, 0, 19, 20}},
	}
	for _, tc := range cases {
		got := pageWindow(tc.current, tc.pages)
		if len(got) != len(tc.want) {
			t.Errorf("pageWindow(%d,%d) = %v, want %v", tc.current, tc.pages, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("pageWindow(%d,%d) = %v, want %v", tc.current, tc.pages, got, tc.want)
				break
			}
		}
	}
}

// The pager must survive the edges: no rows at all, and a page number past the
// end (a stale bookmark, or a filter that shrank the result set).
func TestPagerEdgeCases(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	empty := buildPager(req, sourcesPath, 1, 100, 0, "source")
	if empty.Show {
		t.Error("an empty table should not show a pager")
	}
	if !strings.Contains(empty.Summary, "0 sources") {
		t.Errorf("empty summary = %q", empty.Summary)
	}

	past := buildPager(req, sourcesPath, 99, 25, 30, "source")
	if past.HasNext {
		t.Error("a page past the end should not offer a next page")
	}
	if !strings.Contains(past.Summary, "of 30 sources") {
		t.Errorf("summary = %q", past.Summary)
	}

	one := buildPager(req, sourcesPath, 1, 25, 1, "source")
	if !strings.Contains(one.Summary, "1 source") || strings.Contains(one.Summary, "1 sources") {
		t.Errorf("a single row should read in the singular: %q", one.Summary)
	}
}

// A hand-edited ?size= must not become an unbounded LIMIT.
func TestPageSizeIsRestrictedToTheOfferedValues(t *testing.T) {
	srv, st := testServer(t)
	seed(t, st)
	cookie := login(t, srv)

	seedMany(t, st, 300)
	for _, q := range []string{"/sources?size=999999", "/sources?size=0", "/sources?size=-1", "/sources?size=abc"} {
		rec := get(t, srv, cookie, q)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d", q, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), `href="/sources?size=25"`) {
			t.Errorf("GET %s did not fall back to the default page size", q)
		}
	}
}

// Every table on the site should be filterable and, unless it is a live stream,
// paginated. This is a structural check: the topbar filter only acts on tables
// marked data-search-target, and paginate.js only on a tbody marked
// data-paginate, so an unmarked table silently has neither.
func TestEveryTableIsFilterableAndPaged(t *testing.T) {
	srv, st := testServer(t)
	seed(t, st)
	cookie := login(t, srv)

	seedMany(t, st, 300)

	// The sources table pages on the server (the row set is unbounded), so it
	// carries a rendered pager rather than the data-paginate marker. The
	// dashboard's tables are bounded by construction (a top-8), so they need
	// neither — filtering alone is right there.
	serverPaged := map[string]bool{"/sources": true}
	bounded := map[string]bool{"/": true, "/live": true}

	for _, p := range []string{"/", "/sources", "/signatures", "/sources/198.51.100.7", "/timeline", "/live"} {
		body := get(t, srv, cookie, p).Body.String()
		tables := strings.Count(body, "<table")
		if tables == 0 {
			continue
		}
		if n := strings.Count(body, "data-search-target"); n != tables {
			t.Errorf("%s has %d tables but %d marked filterable", p, tables, n)
		}
		switch {
		case serverPaged[p]:
			if !strings.Contains(body, "pager-page") && !strings.Contains(body, "pager-summary") {
				t.Errorf("%s should render a server-side pager", p)
			}
		case bounded[p]:
			// Bounded by construction: the dashboard shows a top-N, and the live
			// stream prepends rows continuously (paginating it would move the
			// reader's page out from under them; it is capped in JS instead).
		default:
			if n := strings.Count(body, "data-paginate"); n != tables {
				t.Errorf("%s has %d tables but %d marked paginated", p, tables, n)
			}
		}
	}
}

func TestHealthzIsPublic(t *testing.T) {
	srv, _ := testServer(t)
	rec := get(t, srv, nil, "/healthz")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "ok") {
		t.Errorf("healthz = %d %q", rec.Code, rec.Body.String())
	}
}

func TestStaticAssetsAreServed(t *testing.T) {
	srv, _ := testServer(t)
	for _, p := range []string{"/static/style.css", "/static/topbar.js", "/static/live.js", "/static/paginate.js", "/static/ui.js"} {
		if rec := get(t, srv, nil, p); rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d", p, rec.Code)
		}
	}
}

func TestLogout(t *testing.T) {
	srv, _ := testServer(t)
	cookie := login(t, srv)
	if rec := post(t, srv, cookie, "/logout", nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("logout = %d", rec.Code)
	}
	if rec := get(t, srv, cookie, "/"); rec.Code != http.StatusSeeOther {
		t.Error("the session still works after logout")
	}
}

// Signature text and AS names come from rule files and WHOIS data, so they are
// not trusted input. They must be escaped everywhere they are rendered.
func TestUntrustedTextIsEscaped(t *testing.T) {
	srv, st := testServer(t)
	if err := st.RecordAlerts([]store.Alert{{
		Ts: time.Now().UTC(), SrcIP: "198.51.100.7", DestIP: "192.0.2.1", DestPort: 22,
		Proto: "TCP", SID: 9001, Severity: 2, Action: "allowed",
		Sig:   `<script>alert(1)</script>`,
		ASOrg: `<img src=x onerror=alert(2)>`, ASN: 64500,
	}}); err != nil {
		t.Fatalf("record: %v", err)
	}
	cookie := login(t, srv)

	for _, p := range []string{"/", "/sources", "/sources/198.51.100.7", "/live"} {
		body := get(t, srv, cookie, p).Body.String()
		if strings.Contains(body, "<script>alert(1)</script>") {
			t.Errorf("%s rendered a signature name unescaped", p)
		}
		if strings.Contains(body, "<img src=x onerror") {
			t.Errorf("%s rendered an AS name unescaped", p)
		}
	}
}

// The look is shared with birdy on purpose: an operator moving between the two
// consoles should not have to re-learn anything. These assert the mechanics of
// that shared system rather than its appearance, which a test cannot judge.
func TestSharedThemeSystem(t *testing.T) {
	srv, st := testServer(t)
	cookie := login(t, srv)

	t.Run("pre-paint script is render-blocking", func(t *testing.T) {
		body := get(t, srv, cookie, "/").Body.String()
		i := strings.Index(body, "theme-bootstrap.js")
		if i < 0 {
			t.Fatal("no theme-bootstrap script; every navigation would flash the wrong theme")
		}
		// It must NOT be deferred — the whole point is that it runs before the
		// first paint.
		tag := body[max(0, i-120) : i+60]
		if strings.Contains(tag, "defer") {
			t.Errorf("theme-bootstrap is deferred, so it runs after first paint: %s", tag)
		}
	})

	t.Run("theme cookie carries the account preference", func(t *testing.T) {
		if err := st.SaveTheme("dark", "violet", ""); err != nil {
			t.Fatalf("save theme: %v", err)
		}
		rec := get(t, srv, cookie, "/")
		var got string
		for _, c := range rec.Result().Cookies() {
			if c.Name == themeCookieName {
				got = c.Value
			}
		}
		if got != "dark.violet" {
			t.Errorf("theme cookie = %q, want %q", got, "dark.violet")
		}
	})

	t.Run("accent is restricted to the shared palette", func(t *testing.T) {
		post(t, srv, cookie, "/settings/theme", url.Values{"accent": {"neon-pink"}})
		s, _, _ := st.GetSettings()
		if !themeAccents[s.ThemeAccent] {
			t.Errorf("stored accent %q is not one of the shared palette", s.ThemeAccent)
		}
	})

	// The JS pickers apply the change locally and only need an acknowledgement;
	// a redirect would fight the instant client-side update.
	t.Run("fetch requests get 204, plain posts get a redirect", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/settings/theme/mode",
			strings.NewReader(url.Values{"mode": {"dark"}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Requested-With", "fetch")
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Errorf("fetch theme change = %d, want 204", rec.Code)
		}

		plain := post(t, srv, cookie, "/settings/theme/mode", url.Values{"mode": {"light"}})
		if plain.Code != http.StatusSeeOther {
			t.Errorf("plain theme post = %d, want a redirect for the no-JS path", plain.Code)
		}
	})

	// birdy holds density in the browser, not the account, because it is a
	// per-screen choice. meerkat must not reintroduce a server-side density.
	t.Run("no server-side density axis", func(t *testing.T) {
		body := get(t, srv, cookie, "/settings?tab=theme").Body.String()
		if strings.Contains(body, "name=\"density\"") {
			t.Error("a density control reappeared on the server; birdy keeps it in localStorage")
		}
		if !strings.Contains(body, "compact-toggle") {
			t.Error("the compact toggle should be in the top bar, as in birdy")
		}
	})
}

// The shell markup is what makes the two apps feel like one product.
func TestShellMatchesBirdy(t *testing.T) {
	srv, st := testServer(t)
	seed(t, st)
	cookie := login(t, srv)
	body := get(t, srv, cookie, "/").Body.String()

	for _, want := range []string{
		`class="app-shell"`,         // outer frame
		`class="sidebar-brand-row"`, // brand + collapse control
		`class="brand-mark"`,        // the lettermark chip
		`class="nav-copy"`,          // labels that hide when collapsed
		`id="sidebar-collapse"`,     // collapse control
		`id="compact-toggle"`,       // density, held in the browser
		`id="theme-toggle"`,         // light/dark
		`id="command-palette"`,      // the palette
		`class="conn-line"`,         // sidebar status line
		`class="page-eyebrow"`,      // page-top pattern
		`class="breadcrumb"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("shell is missing %s — it should match birdy's", want)
		}
	}
}

// An <svg> with no width/height defaults to 100% of its container, which is how
// the settings page briefly rendered a full-width warning icon. birdy sizes
// icons per context because it never puts a bare one in running text; meerkat
// does, so it needs the base rule. Assert the stylesheet keeps it.
func TestStylesheetSizesBareIcons(t *testing.T) {
	srv, _ := testServer(t)
	css := get(t, srv, nil, "/static/style.css").Body.String()
	if !strings.Contains(css, "svg { width: 18px; height: 18px;") {
		t.Error("no base svg size rule; a bare icon will render at full container width")
	}
	// The two sized graphics must keep their own dimensions.
	for _, sel := range []string{"svg.spark {", "svg.sparkline {"} {
		if !strings.Contains(css, sel) {
			t.Errorf("%s lost its explicit size and would fall back to the base rule", sel)
		}
	}
}

// Every icon a template asks for must actually be defined, or html/template
// renders nothing and the page silently loses its glyph.
func TestEveryReferencedIconIsDefined(t *testing.T) {
	srv, st := testServer(t)
	seed(t, st)
	cookie := login(t, srv)

	for _, p := range []string{"/", "/sources/198.51.100.7", "/live", "/timeline",
		"/settings?tab=ingest", "/settings?tab=geoip", "/settings?tab=blocking",
		"/settings?tab=threats", "/settings?tab=access", "/settings?tab=theme", "/profile"} {
		body := get(t, srv, cookie, p).Body.String()
		// A missing {{template "icon-x"}} is a hard template error, which would
		// truncate the page — so a complete page proves every icon resolved.
		if !strings.Contains(body, "</html>") {
			t.Errorf("%s truncated — an icon template is probably undefined", p)
		}
		if strings.Count(body, "<svg") == 0 {
			t.Errorf("%s rendered no icons at all", p)
		}
	}
}
