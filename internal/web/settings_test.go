package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// Each settings form owns its own columns. A form that writes a neighbour's
// field is the kind of bug that only shows up as a mystery value days later.
func TestSettingsFormsDoNotClobberEachOther(t *testing.T) {
	srv, st := testServer(t)
	cookie := login(t, srv)

	post(t, srv, cookie, "/settings/identity", url.Values{"label": {"edge1"}, "listen": {"0.0.0.0:8100"}})
	post(t, srv, cookie, "/settings/ingest", url.Values{
		"eve_path": {"/var/log/suricata/eve.json"}, "retention_days": {"7"}, "max_events": {"2000000"}})
	post(t, srv, cookie, "/settings/geoip", url.Values{"geoip_dir": {"/var/lib/meerkat"}, "autoupdate": {"on"}})
	post(t, srv, cookie, "/settings/nftably", url.Values{"nftably_url": {"http://127.0.0.1:8099"}, "nftably_token": {"nft"}})
	post(t, srv, cookie, "/settings/threats", url.Values{
		"enabled": {"on"}, "threats_url": {"https://threats.example.net/api/threats/ingest"},
		"threats_token": {"tok"}, "site_name": {"Example Site"}, "site_country": {"RO"},
		"site_lat": {"44.86"}, "site_lng": {"24.87"}, "home_nets": {"10.0.0.0/8"}})
	post(t, srv, cookie, "/settings/theme", url.Values{"accent": {"violet"}})
	// Access goes last, and includes this client: the allow-list takes effect on
	// the very next request, so a list that excludes you locks you out mid-test
	// exactly as it would mid-session.
	post(t, srv, cookie, "/settings/access", url.Values{"access_whitelist": {"192.0.2.0/24"}})

	got, _, err := st.GetSettings()
	if err != nil {
		t.Fatalf("get settings: %v", err)
	}
	for name, pair := range map[string][2]string{
		"RouterLabel":  {got.RouterLabel, "edge1"},
		"ListenAddr":   {got.ListenAddr, "0.0.0.0:8100"},
		"EvePath":      {got.EvePath, "/var/log/suricata/eve.json"},
		"GeoIPDir":     {got.GeoIPDir, "/var/lib/meerkat"},
		"NftablyURL":   {got.NftablyURL, "http://127.0.0.1:8099"},
		"NftablyToken": {got.NftablyToken, "nft"},
		"SiteName":     {got.SiteName, "Example Site"},
		"ThreatsToken": {got.ThreatsToken, "tok"},
		"ThemeAccent":  {got.ThemeAccent, "violet"},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s = %q, want %q — a later form overwrote it", name, pair[0], pair[1])
		}
	}
	if got.RetentionDays != 7 {
		t.Errorf("RetentionDays = %d, want 7", got.RetentionDays)
	}
}

// The allow-list applies from the very next request, with no confirmation step.
// Saving one that does not include you cuts you off immediately — which is why
// loopback is unconditionally allowed and the form says so.
func TestAccessListAppliesImmediatelyAndKeepsLoopbackOpen(t *testing.T) {
	srv, _ := testServer(t)
	cookie := login(t, srv)

	// A list that excludes the caller takes hold at once.
	post(t, srv, cookie, "/settings/access", url.Values{"access_whitelist": {"10.0.0.0/8"}})
	if rec := get(t, srv, cookie, "/settings"); rec.Code != http.StatusForbidden {
		t.Errorf("after excluding itself the client got %d, want 403", rec.Code)
	}

	// ...but loopback still gets in, so an SSH tunnel is always a way back.
	req := httptest.NewRequest(http.MethodGet, "/settings", nil)
	req.RemoteAddr = "127.0.0.1:5555"
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("loopback got %d after a lockout, want 200 — there would be no way back", rec.Code)
	}
}
