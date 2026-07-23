package web

import (
	"context"
	"net/http"
)

const sessionCookieName = "meerkat_session"

type ctxKey int

const ctxUserID ctxKey = 1

// requireAuth wraps a handler so it only runs for requests carrying a valid,
// unexpired session cookie; otherwise it redirects to /login.
func (s *Server) requireAuth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		sess, ok, err := s.store.GetSession(cookie.Value)
		if err != nil {
			s.log.Error("session lookup failed", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		// Refresh the theme cookie on every authenticated request. It is what
		// theme-bootstrap.js reads before first paint, so a browser that has
		// never seen this account still gets the right theme on its first page
		// rather than a flash of the wrong one.
		if st, ok, err := s.store.GetSettings(); err == nil && ok {
			setThemeCookie(w, st.ThemeMode, st.ThemeAccent)
		}

		ctx := context.WithValue(r.Context(), ctxUserID, sess.UserID)
		next(w, r.WithContext(ctx))
	})
}

func setSessionCookie(w http.ResponseWriter, token string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}
