// Package web is meerkat's embedded UI: the sources console, source detail, the
// live tail, settings and the operator timeline. No frontend build step —
// server-rendered html/template pages plus a little vanilla JS.
//
// The home page is a list of SOURCES, not events, and that is the whole design.
// One router produced 891 alerts in four minutes, 85% of them one reputation
// rule restating itself; a raw event list is what meerkat replaces, not what it
// builds. Everything here rolls up per source address — first and last seen,
// event count, distinct signatures, distinct ports, worst severity, triage
// state — because that is the unit an operator can actually act on.
package web

import (
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/floreabogdan/meerkat/internal/geo"
	"github.com/floreabogdan/meerkat/internal/ingest"
	"github.com/floreabogdan/meerkat/internal/nftably"
	"github.com/floreabogdan/meerkat/internal/notify"
	"github.com/floreabogdan/meerkat/internal/rules"
	"github.com/floreabogdan/meerkat/internal/shipper"
	"github.com/floreabogdan/meerkat/internal/store"
	"github.com/floreabogdan/meerkat/internal/triage"
)

// Server is meerkat's HTTP handler: it holds the store, the enricher and a
// handle on the ingester's stats, and serves every route.
type Server struct {
	store *store.Store
	geo   *geo.Enricher
	log   *slog.Logger

	// listenAddr is where meerkat is bound, for the wide-open warning.
	listenAddr string

	// dataDir is where meerkat may store downloaded artifacts (the GeoIP
	// databases) — the directory holding its SQLite file.
	dataDir string

	// ingest reports what the reader is doing. Nil when the server runs without
	// an ingester (tests, or a read-only console over someone else's database).
	ingest *ingest.Ingester

	// shipper publishes to the public threat map. Nil when publishing is off.
	shipper *shipper.Shipper

	// triage turns a decision into a firewall change and a ledger entry. Never
	// nil; it refuses clearly when nftably is not configured.
	triage *triage.Manager

	// auto reports what the block-on-sight rules have been doing. Nil when the
	// server runs without an ingest pipeline.
	auto *triage.Auto

	// rules is the Suricata ruleset manager. Nil on a console with no sensor to
	// manage — the /rules pages then explain themselves rather than 404.
	rules *rules.Manager

	// login throttles failed logins per client IP.
	login *loginLimiter

	// accessMu guards accessList, the parsed access whitelist cached from
	// settings so the per-request gate never hits the database.
	accessMu   sync.RWMutex
	accessList []netip.Prefix

	// notifier delivers alerts to the operator's configured destinations. Never
	// nil — with no destinations every call is a no-op.
	notifier *notify.Dispatcher

	mux *http.ServeMux
}

// Config is the dependency set and options New needs to build a Server.
type Config struct {
	Store      *store.Store
	Geo        *geo.Enricher
	Ingest     *ingest.Ingester
	Shipper    *shipper.Shipper
	Triage     *triage.Manager
	Auto       *triage.Auto
	Rules      *rules.Manager
	Log        *slog.Logger
	ListenAddr string
	DataDir    string
}

// New builds a Server from cfg and wires up the routes.
func New(cfg Config) *Server {
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	s := &Server{
		store:      cfg.Store,
		geo:        cfg.Geo,
		ingest:     cfg.Ingest,
		shipper:    cfg.Shipper,
		triage:     cfg.Triage,
		auto:       cfg.Auto,
		rules:      cfg.Rules,
		log:        log,
		listenAddr: cfg.ListenAddr,
		dataDir:    cfg.DataDir,
		login:      newLoginLimiter(),
		mux:        http.NewServeMux(),
	}
	if s.triage == nil {
		// A server without a triage manager (tests, or a console over someone
		// else's database) still has to render; the manager refuses clearly
		// rather than the handlers nil-checking everywhere.
		s.triage = triage.New(cfg.Store, nftably.New("", "", "meerkat"), log)
	}
	// A 2-minute cooldown collapses a storm of the same alert.
	s.notifier = notify.NewDispatcher(cfg.Store, log, 2*time.Minute)
	s.routes()
	s.reloadAccess()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.accessAllowed(r) {
		// A blocked client gets no HTTP response at all: the connection is
		// closed, so a scanner cannot even tell there is a service listening.
		// Falls back to a bare 403 when the connection cannot be hijacked.
		if hj, ok := w.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				_ = conn.Close()
				return
			}
		}
		w.WriteHeader(http.StatusForbidden)
		return
	}
	setSecurityHeaders(w)
	if !sameOriginWrite(r) {
		http.Error(w, "cross-origin write rejected", http.StatusForbidden)
		return
	}
	s.mux.ServeHTTP(w, r)
}

// sameOriginWrite rejects browser write requests originating on another site.
// SameSite=Strict cookies and CSP form-action already cover modern browsers;
// this validates the request at the server as a separate boundary. Requests
// without browser origin headers remain supported for local CLI automation.
func sameOriginWrite(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return true
	}
	if site := strings.ToLower(r.Header.Get("Sec-Fetch-Site")); site == "cross-site" || site == "same-site" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	expectedScheme := "http"
	if r.TLS != nil {
		expectedScheme = "https"
	}
	return strings.EqualFold(u.Scheme, expectedScheme) && strings.EqualFold(u.Host, r.Host)
}

func (s *Server) routes() {
	// Public
	s.mux.HandleFunc("GET /login", s.handleLoginForm)
	s.mux.HandleFunc("POST /login", s.handleLoginSubmit)
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", staticHandler()))

	// The console. The dashboard is the overview; /sources is the working
	// surface where triage happens. Neither is an event list — everything on
	// both comes from the per-source rollups.
	s.mux.Handle("GET /{$}", s.requireAuth(s.handleDashboard))
	s.mux.Handle("GET /sources", s.requireAuth(s.handleSources))
	s.mux.Handle("GET /sources/{ip}", s.requireAuth(s.handleSourceDetail))
	s.mux.Handle("GET /signatures", s.requireAuth(s.handleSignatures))

	// Managing the sensor rather than only reading it: the rule catalogue, the
	// categories an operator actually has opinions about, and the history of
	// every change made to the ruleset.
	s.mux.Handle("GET /rules", s.requireAuth(s.handleRules))
	s.mux.Handle("GET /rules/{sid}", s.requireAuth(s.handleRuleDetail))
	s.mux.Handle("POST /rules/policy", s.requireAuth(s.handleRulePolicy))
	s.mux.Handle("POST /rules/apply", s.requireAuth(s.handleRulesApply))

	// Acting on the network. Every one is a POST, and every one goes through
	// the triage manager so nftably is called before any state is claimed.
	s.mux.Handle("POST /sources/{ip}/block", s.requireAuth(s.handleSourceBlock))
	s.mux.Handle("POST /sources/{ip}/unblock", s.requireAuth(s.handleSourceUnblock))
	s.mux.Handle("POST /sources/{ip}/acknowledge", s.requireAuth(s.handleSourceAcknowledge))
	s.mux.Handle("POST /sources/{ip}/allowlist", s.requireAuth(s.handleSourceAllowlist))
	s.mux.Handle("POST /sources/bulk", s.requireAuth(s.handleSourcesBulk))
	s.mux.Handle("POST /signatures/disposition", s.requireAuth(s.handleSignatureDisposition))
	s.mux.Handle("GET /live", s.requireAuth(s.handleLive))
	s.mux.Handle("GET /timeline", s.requireAuth(s.handleTimeline))

	s.mux.Handle("GET /settings", s.requireAuth(s.handleSettingsPage))
	s.mux.Handle("POST /settings/identity", s.requireAuth(s.handleSettingsIdentity))
	s.mux.Handle("POST /settings/ingest", s.requireAuth(s.handleSettingsIngest))
	s.mux.Handle("POST /settings/geoip", s.requireAuth(s.handleSettingsGeoIP))
	s.mux.Handle("POST /settings/nftably", s.requireAuth(s.handleSettingsNftably))
	s.mux.Handle("POST /settings/suricata", s.requireAuth(s.handleSettingsSuricata))
	s.mux.Handle("POST /settings/threats", s.requireAuth(s.handleSettingsThreats))
	s.mux.Handle("POST /settings/threats/test", s.requireAuth(s.handleSettingsThreatsTest))
	s.mux.Handle("POST /settings/access", s.requireAuth(s.handleSettingsAccess))
	s.mux.Handle("POST /settings/theme", s.requireAuth(s.handleThemeSave))
	s.mux.Handle("POST /settings/theme/mode", s.requireAuth(s.handleThemeMode))

	s.mux.Handle("GET /profile", s.requireAuth(s.handleProfilePage))
	s.mux.Handle("POST /profile/password", s.requireAuth(s.handleProfilePassword))
	s.mux.Handle("POST /logout", s.requireAuth(s.handleLogout))

	// Authenticated JSON — the live view's poll and the sidebar's ingest dot.
	s.mux.Handle("GET /api/me", s.requireAuth(s.handleAPIMe))
	s.mux.Handle("GET /api/status", s.requireAuth(s.handleAPIStatus))
	s.mux.Handle("GET /api/events", s.requireAuth(s.handleAPIEvents))
}

// reloadAccess refreshes the cached access whitelist from settings. Called at
// startup and whenever the whitelist is edited.
func (s *Server) reloadAccess() {
	var list []netip.Prefix
	if settings, ok, err := s.store.GetSettings(); err == nil && ok {
		list, _ = store.ParseAccessWhitelist(settings.AccessWhitelist)
	}
	s.accessMu.Lock()
	s.accessList = list
	s.accessMu.Unlock()
}

func (s *Server) accessAllowed(r *http.Request) bool {
	ip := clientAddr(r)
	if !ip.IsValid() {
		return false // a malformed peer address must not bypass the allow-list
	}
	s.accessMu.RLock()
	defer s.accessMu.RUnlock()
	return store.AccessAllowed(s.accessList, ip)
}

// WideOpen reports whether meerkat is reachable from any IP with no access
// restriction — the fresh-install default, worth warning about once at startup.
func (s *Server) WideOpen() bool {
	if host, _, err := net.SplitHostPort(s.listenAddr); err == nil {
		if host == "localhost" {
			return false // loopback-only: nothing off-box can reach it
		}
		if ip, err := netip.ParseAddr(host); err == nil && ip.IsLoopback() {
			return false
		}
	}
	s.accessMu.RLock()
	defer s.accessMu.RUnlock()
	return !store.AccessRestricted(s.accessList)
}

// clientAddr is the request's real TCP peer address — never a spoofable
// X-Forwarded-For header, since meerkat is reached directly or over an SSH
// tunnel, not behind a proxy.
func clientAddr(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap()
}

// setSecurityHeaders hardens every response. meerkat serves only its own
// embedded assets and is never framed, so the policy can be tight: no external
// resource loads, no framing, forms post only to meerkat itself, and both styles
// and scripts must come from embedded static assets — no inline anything. The
// templates carry zero inline style attributes, so 'unsafe-inline' is not needed.
func setSecurityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "same-origin")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
	h.Set("Content-Security-Policy",
		"default-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; "+
			"frame-ancestors 'none'; img-src 'self' data:; "+
			"style-src 'self'; script-src 'self'")
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}
