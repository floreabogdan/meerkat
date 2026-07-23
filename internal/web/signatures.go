package web

import (
	"net/http"

	"github.com/floreabogdan/meerkat/internal/store"
)

// signatures.go lists the rules that have fired, loudest first, with a
// disposition control on each.
//
// This is where the finding that motivated the whole project becomes
// actionable: on edge1, two reputation rules accounted for the great majority of
// the volume, and neither was an incident. Muting one is a click here.
//
// The dispositions are recorded now and honoured by the notifier in Phase 3;
// nothing here changes what is ingested or stored, so a muted rule still shows
// up in the console and on a source's history. Muting is about what interrupts
// you, not about discarding evidence — that distinction matters, because a
// muted rule is exactly the kind of thing someone will need to go back and
// read after an incident.
type signaturesVM struct {
	nav
	Signatures []store.Signature
	Total      int64
	Done       string
	Err        string
}

func (s *Server) handleSignatures(w http.ResponseWriter, r *http.Request) {
	sigs, err := s.store.TopSignatures(500)
	if err != nil {
		s.serverError(w, "top signatures", err)
		return
	}
	counts, err := s.store.Summary()
	if err != nil {
		s.serverError(w, "summary", err)
		return
	}
	render(w, s.log, "signatures.html", signaturesVM{
		nav:        s.navFor(r, "signatures"),
		Signatures: sigs,
		Total:      max(counts.Events, 1),
		Done:       r.URL.Query().Get("done"),
		Err:        r.URL.Query().Get("err"),
	})
}
