package web

import (
	"net/http"
	"path/filepath"
	"strings"

	"github.com/floreabogdan/meerkat/internal/geo"
	"github.com/floreabogdan/meerkat/internal/rules"
	"github.com/floreabogdan/meerkat/internal/shipper"
	"github.com/floreabogdan/meerkat/internal/store"
	"github.com/floreabogdan/meerkat/internal/triage"
	"golang.org/x/crypto/bcrypt"
)

type settingsVM struct {
	nav
	Tab      string
	Settings store.Settings
	// Resolved GeoIP paths — what the server will actually open, after the
	// directory defaults are applied.
	ASNPath     string
	CountryPath string
	CityPath    string
	GeoStatus   string
	Counts      store.Counts
	Ingest      ingestVM
	Ship        shipVM
	HomeNets    string
	HomeNetErrs []string
	WideOpen    bool
	AccessErrs  []string
	// RuleStatus describes the sensor meerkat is managing, so the Suricata tab
	// can say whether the paths it is showing actually resolve to anything.
	RuleStatus   rules.Status
	RulesManaged bool
	AutoStats    triage.AutoStats
	UpdateHours  []int
	Saved        string
	Err          string
	Version      string
}

func (s *Server) handleSettingsPage(w http.ResponseWriter, r *http.Request) {
	settings, _, err := s.store.GetSettings()
	if err != nil {
		s.serverError(w, "get settings", err)
		return
	}
	counts, err := s.store.Summary()
	if err != nil {
		s.serverError(w, "summary", err)
		return
	}

	asn, country, city := ResolveGeoPaths(settings, s.dataDir)
	vm := settingsVM{
		nav:         s.navFor(r, "settings"),
		Tab:         tabParam(r, "ingest", "geoip", "blocking", "suricata", "threats", "access", "theme"),
		Settings:    settings,
		ASNPath:     asn,
		CountryPath: country,
		CityPath:    city,
		Counts:      counts,
		Ingest:      s.ingestVM(),
		WideOpen:    s.WideOpen(),
		Saved:       r.URL.Query().Get("saved"),
		Err:         r.URL.Query().Get("err"),
	}
	if s.geo != nil {
		vm.GeoStatus = s.geo.Describes()
	}
	_, vm.AccessErrs = store.ParseAccessWhitelist(settings.AccessWhitelist)

	// Show the effective home networks, so the operator sees what is actually
	// protecting customer addresses rather than an empty box that looks like
	// "nothing is excluded".
	vm.HomeNets = settings.HomeNets
	if strings.TrimSpace(vm.HomeNets) == "" {
		vm.HomeNets = shipper.DefaultHomeNets
	}
	_, vm.HomeNetErrs = store.ParsePrefixList(vm.HomeNets)
	vm.Ship = s.shipVM()

	vm.UpdateHours = updateHours
	if s.rules != nil {
		vm.RulesManaged = true
		if status, err := s.rules.Status(); err != nil {
			s.log.Warn("could not read the rule manager status", "err", err)
		} else {
			vm.RuleStatus = status
		}
	}
	if s.auto != nil {
		vm.AutoStats = s.auto.Stats()
	}

	render(w, s.log, "settings.html", vm)
}

// ResolveGeoPaths works out which .mmdb files the server should open: an
// explicit path wins, otherwise the standard DB-IP filename inside the GeoIP
// directory (which itself defaults to the data directory). Exported because the
// server command needs the same answer before the web layer exists.
func ResolveGeoPaths(settings store.Settings, dataDir string) (asn, country, city string) {
	dir := settings.GeoIPDir
	if dir == "" {
		dir = dataDir
	}
	pick := func(explicit string, kind geo.Kind) string {
		if explicit != "" {
			return explicit
		}
		if dir == "" {
			return ""
		}
		return filepath.Join(dir, kind.Filename())
	}
	return pick(settings.GeoIPASNDB, geo.KindASN),
		pick(settings.GeoIPCountryDB, geo.KindCountry),
		pick(settings.GeoIPCityDB, geo.KindCity)
}

func (s *Server) handleSettingsIdentity(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/settings?err="+urlEscape("could not read the form"), http.StatusSeeOther)
		return
	}
	label := strings.TrimSpace(r.FormValue("label"))
	listen := strings.TrimSpace(r.FormValue("listen"))
	if err := s.store.SaveIdentity(label, listen); err != nil {
		s.serverError(w, "save identity", err)
		return
	}
	s.audit(r, store.AuditSettings, "updated the router label and listen address")
	http.Redirect(w, r, "/settings?saved=identity", http.StatusSeeOther)
}

func (s *Server) handleSettingsIngest(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/settings?tab=ingest&err="+urlEscape("could not read the form"), http.StatusSeeOther)
		return
	}
	evePath := strings.TrimSpace(r.FormValue("eve_path"))
	statePath := strings.TrimSpace(r.FormValue("state_path"))
	// Clamped rather than validated-and-rejected: every value in range is
	// sensible, and a settings form should not be able to store -3 days.
	retention := formInt(r, "retention_days", 7, 1, 3650)
	maxEvents := formInt64(r, "max_events", 2_000_000, 1000, 1_000_000_000)

	if err := s.store.SaveIngest(evePath, statePath, retention, maxEvents); err != nil {
		s.serverError(w, "save ingest settings", err)
		return
	}
	s.audit(r, store.AuditSettings, "updated ingest and retention settings")
	http.Redirect(w, r, "/settings?tab=ingest&saved=ingest", http.StatusSeeOther)
}

func (s *Server) handleSettingsGeoIP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/settings?tab=geoip&err="+urlEscape("could not read the form"), http.StatusSeeOther)
		return
	}
	if err := s.store.SaveGeoIP(
		strings.TrimSpace(r.FormValue("geoip_dir")),
		strings.TrimSpace(r.FormValue("asn_db")),
		strings.TrimSpace(r.FormValue("country_db")),
		strings.TrimSpace(r.FormValue("city_db")),
		r.FormValue("autoupdate") == "on",
	); err != nil {
		s.serverError(w, "save geoip settings", err)
		return
	}
	s.audit(r, store.AuditSettings, "updated GeoIP settings")
	http.Redirect(w, r, "/settings?tab=geoip&saved=geoip", http.StatusSeeOther)
}

func (s *Server) handleSettingsNftably(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/settings?tab=blocking&err="+urlEscape("could not read the form"), http.StatusSeeOther)
		return
	}
	url := strings.TrimRight(strings.TrimSpace(r.FormValue("nftably_url")), "/")
	token := strings.TrimSpace(r.FormValue("nftably_token"))
	// A blank token field means "leave it alone", so re-saving the URL does not
	// silently wipe a token the form never displays back.
	if token == "" {
		if cur, ok, err := s.store.GetSettings(); err == nil && ok {
			token = cur.NftablyToken
		}
	}
	if err := s.store.SaveNftably(url, token); err != nil {
		s.serverError(w, "save nftably settings", err)
		return
	}
	s.audit(r, store.AuditSettings, "updated the nftably block endpoint")
	http.Redirect(w, r, "/settings?tab=blocking&saved=blocking", http.StatusSeeOther)
}

// updateHours is the schedule picker's range.
var updateHours = []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}

// handleSettingsSuricata saves where the sensor's files live and how much
// meerkat is allowed to do to them without being asked.
//
// The two switches here are the ones with teeth. Auto-update pulls a fresh
// ruleset onto a live inline sensor on a schedule; blocking on sight changes
// the firewall with nobody watching. Both default to off, and both stay off
// until somebody turns them on here.
func (s *Server) handleSettingsSuricata(w http.ResponseWriter, r *http.Request) {
	back := "/settings?tab=suricata"
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, back+"&err="+urlEscape("could not read the form"), http.StatusSeeOther)
		return
	}
	cur, ok, err := s.store.GetSettings()
	if err != nil || !ok {
		s.serverError(w, "get settings", err)
		return
	}

	cur.SuricataRulesPath = strings.TrimSpace(r.FormValue("rules_path"))
	cur.SuricataConfDir = strings.TrimRight(strings.TrimSpace(r.FormValue("conf_dir")), "/")
	cur.SuricataSocket = strings.TrimSpace(r.FormValue("socket"))
	cur.SuricataDataDir = strings.TrimRight(strings.TrimSpace(r.FormValue("data_dir")), "/")
	cur.RulesAutoUpdate = r.FormValue("auto_update") == "1"
	cur.RulesUpdateHour = formInt(r, "update_hour", 4, 0, 23)
	cur.AutoBlockEnabled = r.FormValue("autoblock") == "1"
	// A cap of zero would mean "never auto-block", which is what the switch is
	// for; clamp to at least one so the two controls cannot contradict.
	cur.AutoBlockMaxHour = formInt(r, "autoblock_max", 20, 1, 1000)

	if err := s.store.SaveSuricata(cur); err != nil {
		http.Redirect(w, r, back+"&err="+urlEscape(err.Error()), http.StatusSeeOther)
		return
	}
	what := "updated the suricata rule-management settings"
	if cur.AutoBlockEnabled {
		what += "; blocking on sight is ON, capped at " + itoa(cur.AutoBlockMaxHour) + " per hour"
	}
	s.audit(r, store.AuditSettings, what)
	http.Redirect(w, r, back+"&saved=suricata", http.StatusSeeOther)
}

// handleSettingsThreats saves the public threat map's configuration.
func (s *Server) handleSettingsThreats(w http.ResponseWriter, r *http.Request) {
	back := "/settings?tab=threats"
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, back+"&err="+urlEscape("could not read the form"), http.StatusSeeOther)
		return
	}
	cur, _, err := s.store.GetSettings()
	if err != nil {
		s.serverError(w, "get settings", err)
		return
	}

	cur.ThreatsEnabled = r.FormValue("enabled") == "on"
	cur.ThreatsURL = strings.TrimSpace(r.FormValue("threats_url"))
	cur.SiteName = strings.TrimSpace(r.FormValue("site_name"))
	cur.SiteCountry = strings.ToUpper(strings.TrimSpace(r.FormValue("site_country")))
	cur.SiteLat = formFloat(r, "site_lat", cur.SiteLat, -90, 90)
	cur.SiteLng = formFloat(r, "site_lng", cur.SiteLng, -180, 180)
	cur.HomeNets = r.FormValue("home_nets")

	// A blank token means "leave it alone", so re-saving the form does not wipe
	// a token it never displays back.
	if token := strings.TrimSpace(r.FormValue("threats_token")); token != "" {
		cur.ThreatsToken = token
	}

	if _, errs := store.ParsePrefixList(cur.HomeNets); len(errs) > 0 {
		http.Redirect(w, r, back+"&err="+urlEscape(strings.Join(errs, " ")), http.StatusSeeOther)
		return
	}
	// Refuse to publish without a site: the collector rejects a nameless batch,
	// and a site at (0,0) would draw every arc to the Atlantic.
	if cur.ThreatsEnabled && (cur.SiteName == "" || (cur.SiteLat == 0 && cur.SiteLng == 0)) {
		http.Redirect(w, r, back+"&err="+urlEscape("Publishing needs a site name and its coordinates."), http.StatusSeeOther)
		return
	}
	if cur.ThreatsEnabled && (cur.ThreatsURL == "" || cur.ThreatsToken == "") {
		http.Redirect(w, r, back+"&err="+urlEscape("Publishing needs the collector URL and its ingest token."), http.StatusSeeOther)
		return
	}

	if err := s.store.SaveThreats(cur); err != nil {
		s.serverError(w, "save threats settings", err)
		return
	}
	s.audit(r, store.AuditSettings, "updated the threat-map publisher")
	http.Redirect(w, r, back+"&saved=threats", http.StatusSeeOther)
}

// handleSettingsThreatsTest publishes one synthetic detection so the operator
// can confirm the endpoint and token before turning publishing on.
func (s *Server) handleSettingsThreatsTest(w http.ResponseWriter, r *http.Request) {
	back := "/settings?tab=threats"
	if s.shipper == nil {
		http.Redirect(w, r, back+"&err="+urlEscape("Publishing is not configured, so there is nothing to test."), http.StatusSeeOther)
		return
	}
	if err := s.shipper.Test(r.Context()); err != nil {
		http.Redirect(w, r, back+"&err="+urlEscape("Test failed: "+err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, back+"&saved=threatstest", http.StatusSeeOther)
}

func (s *Server) handleSettingsAccess(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/settings?tab=access&err="+urlEscape("could not read the form"), http.StatusSeeOther)
		return
	}
	list := r.FormValue("access_whitelist")
	if _, errs := store.ParseAccessWhitelist(list); len(errs) > 0 {
		http.Redirect(w, r, "/settings?tab=access&err="+urlEscape(strings.Join(errs, " ")), http.StatusSeeOther)
		return
	}
	if err := s.store.SaveAccessWhitelist(list); err != nil {
		s.serverError(w, "save access whitelist", err)
		return
	}
	s.reloadAccess()
	s.audit(r, store.AuditSettings, "updated the access allow-list")
	http.Redirect(w, r, "/settings?tab=access&saved=access", http.StatusSeeOther)
}

// Theme axes, matching birdy exactly so the two feel like one product: a
// light/dark mode and an accent hue. birdy dropped the third (density) axis in
// favour of a compact toggle held in the browser, so meerkat has no density
// setting either.
var (
	themeModes   = map[string]bool{"": true, "system": true, "light": true, "dark": true}
	themeAccents = map[string]bool{"green": true, "ocean": true, "violet": true, "amber": true}
)

// themeCookieName carries the saved theme to the page so theme-bootstrap.js can
// stamp it onto <html> before first paint. The database is still the source of
// truth; this only exists to avoid a flash of the wrong theme.
const themeCookieName = "meerkat_theme"

// setThemeCookie mirrors the stored preference into the cookie the pre-paint
// script reads. Not HttpOnly on purpose — that script has to read it.
func setThemeCookie(w http.ResponseWriter, mode, accent string) {
	if mode == "" {
		mode = "system"
	}
	if accent == "" {
		accent = "green"
	}
	http.SetCookie(w, &http.Cookie{
		Name:     themeCookieName,
		Value:    mode + "." + accent,
		Path:     "/",
		MaxAge:   365 * 24 * 60 * 60,
		SameSite: http.SameSiteLaxMode,
	})
}

// handleThemeSave stores the accent. The page has already applied it locally, so
// this answers 204 rather than redirecting — a redirect would fight the
// instant client-side change.
func (s *Server) handleThemeSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	cur, _, err := s.store.GetSettings()
	if err != nil {
		s.serverError(w, "get settings", err)
		return
	}
	accent := r.FormValue("accent")
	if !themeAccents[accent] {
		accent = "green"
	}
	mode := cur.ThemeMode
	if err := s.store.SaveTheme(mode, accent, ""); err != nil {
		s.serverError(w, "save theme", err)
		return
	}
	setThemeCookie(w, mode, accent)
	themeResponse(w, r, "/settings?tab=theme")
}

// handleThemeMode stores the light/dark choice.
func (s *Server) handleThemeMode(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	cur, _, err := s.store.GetSettings()
	if err != nil {
		s.serverError(w, "get settings", err)
		return
	}

	mode := r.FormValue("mode")
	if !themeModes[mode] {
		// No explicit mode: this is the no-JS fallback, so flip the current one.
		mode = "dark"
		if cur.ThemeMode == "dark" {
			mode = "light"
		}
	}
	if mode == "system" {
		mode = ""
	}
	accent := cur.ThemeAccent
	if !themeAccents[accent] {
		accent = "green"
	}
	if err := s.store.SaveTheme(mode, accent, ""); err != nil {
		s.serverError(w, "save theme", err)
		return
	}
	setThemeCookie(w, mode, accent)

	back := r.Header.Get("Referer")
	if !isLocalPath(back) {
		back = "/"
	}
	themeResponse(w, r, back)
}

// themeResponse answers a theme change. The JS pickers apply the change
// themselves and only need an acknowledgement; a plain form post (no JS) still
// needs somewhere to go.
func themeResponse(w http.ResponseWriter, r *http.Request, back string) {
	if r.Header.Get("X-Requested-With") == "fetch" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// isLocalPath keeps a redirect on this site: only a rooted path, never a
// scheme, host or protocol-relative URL.
//
// The backslash case is the one that is easy to miss. Browsers normalise "\" to
// "/" in the authority part of a URL, so "/\evil.example" is fetched as
// "//evil.example" — a host, not a path. Checking only for a leading "//" lets
// it straight through, and the "back" parameter on every form here would become
// an open redirect.
func isLocalPath(s string) bool {
	if len(s) < 1 || s[0] != '/' {
		return false
	}
	if len(s) > 1 && (s[1] == '/' || s[1] == '\\') {
		return false
	}
	// A control character can be stripped by a browser before parsing, which
	// turns "/\tevil.example" into something else again.
	return !strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

type profileVM struct {
	nav
	Saved string
	Err   string
}

func (s *Server) handleProfilePage(w http.ResponseWriter, r *http.Request) {
	render(w, s.log, "profile.html", profileVM{
		nav:   s.navFor(r, "profile"),
		Saved: r.URL.Query().Get("saved"),
		Err:   r.URL.Query().Get("err"),
	})
}

func (s *Server) handleProfilePassword(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/profile?err="+urlEscape("could not read the form"), http.StatusSeeOther)
		return
	}
	current := r.FormValue("current")
	next := r.FormValue("password")
	confirm := r.FormValue("confirm")

	user := s.currentUser(r)
	if user.ID == 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(current)) != nil {
		http.Redirect(w, r, "/profile?err="+urlEscape("The current password is not correct."), http.StatusSeeOther)
		return
	}
	if len(next) < 8 {
		http.Redirect(w, r, "/profile?err="+urlEscape("The new password must be at least 8 characters."), http.StatusSeeOther)
		return
	}
	if next != confirm {
		http.Redirect(w, r, "/profile?err="+urlEscape("The two new passwords do not match."), http.StatusSeeOther)
		return
	}

	hash, err := HashPassword(next)
	if err != nil {
		s.serverError(w, "hash password", err)
		return
	}
	if err := s.store.SetPassword(user.ID, hash); err != nil {
		s.serverError(w, "set password", err)
		return
	}
	// Every other session for this account was created under the old password;
	// it must not outlive it.
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		if err := s.store.DeleteUserSessionsExcept(user.ID, cookie.Value); err != nil {
			s.log.Warn("could not clear other sessions", "error", err)
		}
	}
	s.audit(r, store.AuditSettings, "changed their password")
	http.Redirect(w, r, "/profile?saved=password", http.StatusSeeOther)
}

type timelineVM struct {
	nav
	Entries []store.AuditEntry
	NextURL string
}

func (s *Server) handleTimeline(w http.ResponseWriter, r *http.Request) {
	const pageSize = 100
	before := int64Param(r, "before", 0)
	entries, err := s.store.ListAudit(pageSize, before)
	if err != nil {
		s.serverError(w, "list audit", err)
		return
	}
	vm := timelineVM{nav: s.navFor(r, "timeline"), Entries: entries}
	if len(entries) == pageSize {
		vm.NextURL = "/timeline?before=" + itoa64(entries[len(entries)-1].ID)
	}
	render(w, s.log, "timeline.html", vm)
}
