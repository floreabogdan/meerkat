package web

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/floreabogdan/meerkat/internal/store"
)

// audit records an operator action on the timeline, attributed to the logged-in
// user. Best-effort: a failed audit write never blocks the action.
func (s *Server) audit(r *http.Request, kind, message string) {
	_ = s.store.InsertAudit(s.currentUser(r).Username, kind, message)
}

// urlEscape encodes a value for a query string (used for ?err= flash messages).
func urlEscape(s string) string { return url.QueryEscape(s) }

// serverError logs the real cause and shows the user a generic message. SQL
// text and file paths are for the journal, not the browser.
func (s *Server) serverError(w http.ResponseWriter, what string, err error) {
	s.log.Error(what, "error", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

// currentUserID returns the logged-in user's id from the request context, set
// by requireAuth.
func currentUserID(r *http.Request) int64 {
	id, _ := r.Context().Value(ctxUserID).(int64)
	return id
}

// currentUser looks up the logged-in user. On any failure it returns a zero
// User — callers use it only for display and attribution, never as a security
// decision.
func (s *Server) currentUser(r *http.Request) store.User {
	u, _, err := s.store.GetUserByID(currentUserID(r))
	if err != nil {
		s.log.Warn("current user lookup failed", "error", err)
	}
	return u
}

// nav is the shared header data every authenticated page needs.
type nav struct {
	Active      string
	RouterLabel string
	Username    string
}

// navFor builds the shell data. The theme is deliberately NOT here: it reaches
// the page through a cookie that theme-bootstrap.js stamps onto <html> before
// first paint, which is what stops a dark-mode operator seeing a white flash on
// every navigation. Rendering it into the markup instead would arrive too late.
func (s *Server) navFor(r *http.Request, active string) nav {
	n := nav{Active: active, Username: s.currentUser(r).Username}
	if st, ok, err := s.store.GetSettings(); err == nil && ok {
		n.RouterLabel = st.RouterLabel
	}
	return n
}

// tabParam returns the requested ?tab= value if it is one of the allowed tabs,
// otherwise the first allowed tab (the default).
func tabParam(r *http.Request, allowed ...string) string {
	want := r.URL.Query().Get("tab")
	for _, a := range allowed {
		if a == want {
			return a
		}
	}
	return allowed[0]
}

// intParam reads a bounded integer query parameter, falling back to def when it
// is absent or unparseable.
func intParam(r *http.Request, name string, def int) int {
	v := strings.TrimSpace(r.URL.Query().Get(name))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

// int64Param is intParam for the wider counters.
func int64Param(r *http.Request, name string, def int64) int64 {
	v := strings.TrimSpace(r.URL.Query().Get(name))
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return def
	}
	return n
}

// formInt reads a bounded integer form field, clamping to [lo, hi] and falling
// back to def when absent or unparseable — a settings form should never be able
// to store a retention of -3 days.
func formInt(r *http.Request, name string, def, lo, hi int) int {
	n, err := strconv.Atoi(strings.TrimSpace(r.FormValue(name)))
	if err != nil {
		return def
	}
	return min(max(n, lo), hi)
}

// strconvAtoi is strconv.Atoi under a name that does not collide with the
// package-level helpers above.
func strconvAtoi(v string) (int, error) { return strconv.Atoi(strings.TrimSpace(v)) }

// formFloat reads a bounded float form field — a latitude that is not a number,
// or is outside the globe, must not reach a map.
func formFloat(r *http.Request, name string, def, lo, hi float64) float64 {
	v, err := strconv.ParseFloat(strings.TrimSpace(r.FormValue(name)), 64)
	if err != nil {
		return def
	}
	return min(max(v, lo), hi)
}

func formInt64(r *http.Request, name string, def, lo, hi int64) int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(r.FormValue(name)), 10, 64)
	if err != nil {
		return def
	}
	return min(max(n, lo), hi)
}
