package web

import (
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/floreabogdan/meerkat/internal/store"
)

// actions.go is where an operator's decision becomes a change to the network.
//
// Every handler here is a POST behind the session, the access list and the
// same-origin check, and every one records to the actions ledger through the
// triage manager — including the failures. Nothing writes "blocked" without
// nftably having confirmed it first.

// blockTTLs are the offered durations. A timed block is the common case for a
// noisy scanner: long enough to stop the burst, short enough that nobody has to
// remember to undo it.
var blockTTLs = []struct {
	Value string
	Label string
	Dur   time.Duration
}{
	{"", "Until I unblock it", 0},
	{"1h", "1 hour", time.Hour},
	{"24h", "24 hours", 24 * time.Hour},
	{"7d", "7 days", 7 * 24 * time.Hour},
	{"30d", "30 days", 30 * 24 * time.Hour},
}

func parseTTL(v string) time.Duration {
	for _, t := range blockTTLs {
		if t.Value == v {
			return t.Dur
		}
	}
	return 0
}

// sourceRedirect sends the operator back where they came from with a flash.
// The referer is only honoured when it is a local path, so it can never become
// an open redirect.
func (s *Server) sourceRedirect(w http.ResponseWriter, r *http.Request, ip, msg, errMsg string) {
	back := r.FormValue("back")
	if !isLocalPath(back) {
		back = "/sources/" + ip
	}
	sep := "?"
	if strings.Contains(back, "?") {
		sep = "&"
	}
	switch {
	case errMsg != "":
		back += sep + "err=" + urlEscape(errMsg)
	case msg != "":
		back += sep + "done=" + urlEscape(msg)
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// pathIP validates the {ip} path segment. A source key is always an address, so
// anything else is refused before it can reach the store or nftably.
func pathIP(r *http.Request) (string, bool) {
	ip := r.PathValue("ip")
	if _, err := netip.ParseAddr(ip); err != nil {
		return "", false
	}
	return ip, true
}

func (s *Server) handleSourceBlock(w http.ResponseWriter, r *http.Request) {
	ip, ok := pathIP(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.sourceRedirect(w, r, ip, "", "could not read the form")
		return
	}
	reason := strings.TrimSpace(r.FormValue("reason"))
	ttl := parseTTL(r.FormValue("ttl"))

	out, err := s.triage.Block(r.Context(), ip, reason, ttl, s.currentUser(r).Username)
	if err != nil {
		s.sourceRedirect(w, r, ip, "", err.Error())
		return
	}
	msg := out.Message
	if !out.Live {
		// nftably recorded the block but has not pushed it to the kernel, so
		// traffic is still flowing. Saying "blocked" here would be the exact
		// overclaim this project refuses to make.
		msg += " — not yet dropping traffic; apply the change in nftably"
	}
	s.audit(r, store.AuditSourceChange, "blocked "+ip)
	s.sourceRedirect(w, r, ip, msg, "")
}

func (s *Server) handleSourceUnblock(w http.ResponseWriter, r *http.Request) {
	ip, ok := pathIP(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	_ = r.ParseForm()
	reason := strings.TrimSpace(r.FormValue("reason"))

	out, err := s.triage.Unblock(r.Context(), ip, reason, s.currentUser(r).Username)
	if err != nil {
		s.sourceRedirect(w, r, ip, "", err.Error())
		return
	}
	s.audit(r, store.AuditSourceChange, "unblocked "+ip)
	s.sourceRedirect(w, r, ip, out.Message, "")
}

func (s *Server) handleSourceAcknowledge(w http.ResponseWriter, r *http.Request) {
	ip, ok := pathIP(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	_ = r.ParseForm()
	note := strings.TrimSpace(r.FormValue("reason"))
	if err := s.triage.Acknowledge(ip, note, s.currentUser(r).Username); err != nil {
		s.sourceRedirect(w, r, ip, "", err.Error())
		return
	}
	s.audit(r, store.AuditSourceChange, "acknowledged "+ip)
	s.sourceRedirect(w, r, ip, ip+" marked as reviewed", "")
}

func (s *Server) handleSourceAllowlist(w http.ResponseWriter, r *http.Request) {
	ip, ok := pathIP(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	_ = r.ParseForm()
	note := strings.TrimSpace(r.FormValue("reason"))
	if err := s.triage.Allowlist(ip, note, s.currentUser(r).Username); err != nil {
		s.sourceRedirect(w, r, ip, "", err.Error())
		return
	}
	s.audit(r, store.AuditSourceChange, "allowlisted "+ip)
	s.sourceRedirect(w, r, ip, ip+" allowlisted — it will not be alerted on again", "")
}

// maxBulk caps a bulk action. A filter can select thousands of sources, and
// blocking thousands of addresses from one click — each its own HTTP call to
// nftably — is not something to do by accident.
const maxBulk = 50

// handleSourcesBulk applies one action to the sources ticked on the list.
//
// It deliberately operates on an explicit list of addresses rather than on "the
// current filter": a filter is evaluated at render time, and by the time the
// form is submitted it could match something the operator never saw.
func (s *Server) handleSourcesBulk(w http.ResponseWriter, r *http.Request) {
	back := "/sources"
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, back+"?err="+urlEscape("could not read the form"), http.StatusSeeOther)
		return
	}
	if b := r.FormValue("back"); isLocalPath(b) {
		back = b
	}
	sep := "?"
	if strings.Contains(back, "?") {
		sep = "&"
	}

	ips := r.Form["ip"]
	if len(ips) == 0 {
		http.Redirect(w, r, back+sep+"err="+urlEscape("Select at least one source first."), http.StatusSeeOther)
		return
	}
	if len(ips) > maxBulk {
		http.Redirect(w, r, back+sep+"err="+urlEscape("That selects more than "+itoa(maxBulk)+" sources. Narrow the filter first — this is one firewall call per address."), http.StatusSeeOther)
		return
	}

	action := r.FormValue("action")
	reason := strings.TrimSpace(r.FormValue("reason"))
	if reason == "" {
		reason = "bulk " + action + " from meerkat"
	}
	actor := s.currentUser(r).Username
	ttl := parseTTL(r.FormValue("ttl"))

	var done, failed int
	var firstErr string
	for _, ip := range ips {
		if _, err := netip.ParseAddr(ip); err != nil {
			failed++
			continue
		}
		var err error
		switch action {
		case "block":
			_, err = s.triage.Block(r.Context(), ip, reason, ttl, actor)
		case "unblock":
			_, err = s.triage.Unblock(r.Context(), ip, reason, actor)
		case "acknowledge":
			err = s.triage.Acknowledge(ip, reason, actor)
		case "allowlist":
			err = s.triage.Allowlist(ip, reason, actor)
		default:
			err = errors.New("unknown action")
		}
		if err != nil {
			failed++
			if firstErr == "" {
				firstErr = err.Error()
			}
			continue
		}
		done++
	}

	s.audit(r, store.AuditSourceChange, action+" applied to "+itoa(done)+" sources")

	// Report both halves. A bulk action that half-worked is the case most worth
	// being precise about.
	msg := itoa(done) + " source"
	if done != 1 {
		msg += "s"
	}
	msg += " " + action + "ed"
	if failed > 0 {
		http.Redirect(w, r, back+sep+"err="+urlEscape(msg+"; "+itoa(failed)+" failed — "+firstErr), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, back+sep+"done="+urlEscape(msg), http.StatusSeeOther)
}

// handleSignatureDisposition mutes, digests or restores a signature. Muting the
// reputation feeds is the one-click answer to the flood this project exists to
// tame, so it is reachable straight from the dashboard's loudest-rules list.
func (s *Server) handleSignatureDisposition(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/signatures?err="+urlEscape("could not read the form"), http.StatusSeeOther)
		return
	}
	back := "/signatures"
	if b := r.FormValue("back"); isLocalPath(b) {
		back = b
	}
	sep := "?"
	if strings.Contains(back, "?") {
		sep = "&"
	}

	sid, err := strconvAtoi(r.FormValue("sid"))
	if err != nil {
		http.Redirect(w, r, back+sep+"err="+urlEscape("that is not a signature id"), http.StatusSeeOther)
		return
	}
	disposition := r.FormValue("disposition")
	if err := s.store.SetDisposition(sid, disposition); err != nil {
		http.Redirect(w, r, back+sep+"err="+urlEscape(err.Error()), http.StatusSeeOther)
		return
	}
	target := "sid:" + itoa(sid)
	_ = s.store.RecordAction(store.Action{
		Actor: s.currentUser(r).Username, Action: store.ActionMute, Target: target,
		Reason: "disposition set to " + disposition, Result: "applied", OK: true,
	})
	s.audit(r, store.AuditSourceChange, "set signature "+itoa(sid)+" to "+disposition)
	http.Redirect(w, r, back+sep+"done="+urlEscape("Signature "+itoa(sid)+" set to "+disposition), http.StatusSeeOther)
}
