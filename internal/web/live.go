package web

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/floreabogdan/meerkat/internal/ingest"
)

// live.go is the raw stream — deliberately a secondary page, not the home page.
// Watching alerts scroll past is how you learn what a sensor is doing; it is not
// how you triage. The sources list is where decisions get made.

// maxLivePoll caps how many events one poll returns, so a client that has been
// idle through a flood reconnects with a page rather than a megabyte.
const maxLivePoll = 200

type liveVM struct {
	nav
	Events []eventVM
	// Cursor is the newest event id at render time; the poller asks for
	// everything after it.
	Cursor int64
	Ingest ingestVM
}

func (s *Server) handleLive(w http.ResponseWriter, r *http.Request) {
	events, err := s.store.RecentEvents(100)
	if err != nil {
		s.serverError(w, "recent events", err)
		return
	}
	cursor, err := s.store.MaxEventID()
	if err != nil {
		s.serverError(w, "max event id", err)
		return
	}
	render(w, s.log, "live.html", liveVM{
		nav:    s.navFor(r, "live"),
		Events: decorateEvents(events),
		Cursor: cursor,
		Ingest: s.ingestVM(),
	})
}

// liveEvent is the wire shape of an event for the live view's poll. It is a
// hand-written projection rather than the store type so that widening a column
// never silently changes a public payload.
type liveEvent struct {
	ID        int64  `json:"id"`
	Ts        string `json:"ts"`
	SrcIP     string `json:"srcIp"`
	DestIP    string `json:"destIp"`
	DestPort  int    `json:"destPort"`
	Proto     string `json:"proto"`
	SID       int    `json:"sid"`
	Signature string `json:"signature"`
	Category  string `json:"category"`
	Severity  int    `json:"severity"`
}

// handleAPIEvents is what the live page polls: everything newer than the
// cursor it holds.
func (s *Server) handleAPIEvents(w http.ResponseWriter, r *http.Request) {
	after := int64Param(r, "after", 0)
	events, err := s.store.EventsAfter(after, maxLivePoll)
	if err != nil {
		s.serverError(w, "events after", err)
		return
	}

	out := make([]liveEvent, 0, len(events))
	cursor := after
	for _, e := range events {
		out = append(out, liveEvent{
			ID: e.ID, Ts: e.Ts.UTC().Format(time.RFC3339), SrcIP: e.SrcIP,
			DestIP: e.DestIP, DestPort: e.DestPort, Proto: e.Proto,
			SID: e.SID, Signature: e.Signature, Category: e.Category, Severity: e.Severity,
		})
		cursor = max(cursor, e.ID)
	}
	writeJSON(w, map[string]any{"events": out, "cursor": cursor})
}

// ingestVM is the reader's health, shown in the sidebar and above an empty
// table. An empty console has two very different causes — a quiet network, or a
// reader that is not reading — and they must never look the same.
type ingestVM struct {
	Running     bool
	LinesRead   uint64
	Alerts      uint64
	Written     uint64
	ParseErrors uint64
	LastLineAt  time.Time
	LastAlertAt time.Time
	LastError   string
	// Stale is true when the reader is running but nothing has arrived for a
	// while — the failure mode with no error message.
	Stale bool
}

// staleAfter is how long a silent eve.json goes before the UI stops calling it
// healthy. Suricata writes flow records constantly on a live link, so on a
// working sensor this is only ever reached when something is wrong.
const staleAfter = 10 * time.Minute

func (s *Server) ingestVM() ingestVM {
	if s.ingest == nil {
		return ingestVM{}
	}
	st := s.ingest.Stats()
	vm := ingestVM{
		Running:     true,
		LinesRead:   st.LinesRead,
		Alerts:      st.Alerts,
		Written:     st.Written,
		ParseErrors: st.ParseErrors,
		LastLineAt:  st.LastLineAt,
		LastAlertAt: st.LastAlertAt,
		LastError:   st.LastError,
	}
	vm.Stale = st.LastLineAt.IsZero() || time.Since(st.LastLineAt) > staleAfter
	return vm
}

// shipVM is the threat-map publisher's health, for the settings page.
type shipVM struct {
	Configured bool
	Enabled    bool
	Shipped    int64
	Withheld   int64
	Batches    int64
	Failures   int64
	Cursor     int64
	LastOK     time.Time
	LastError  string
}

func (s *Server) shipVM() shipVM {
	if s.shipper == nil {
		return shipVM{}
	}
	st := s.shipper.Stats()
	return shipVM{
		Configured: true, Enabled: true,
		Shipped: st.Shipped, Withheld: st.Withheld, Batches: st.Batches,
		Failures: st.Failures, Cursor: st.Cursor,
		LastOK: st.LastOK, LastError: st.LastError,
	}
}

// handleAPIMe backs the top-bar avatar, which renders a generic user icon until
// this resolves so it degrades gracefully without JS.
func (s *Server) handleAPIMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"username": s.currentUser(r).Username})
}

// handleAPIStatus backs the sidebar's ingest dot.
func (s *Server) handleAPIStatus(w http.ResponseWriter, r *http.Request) {
	vm := s.ingestVM()
	var stats ingest.Stats
	if s.ingest != nil {
		stats = s.ingest.Stats()
	}
	counts, err := s.store.Summary()
	if err != nil {
		s.serverError(w, "summary", err)
		return
	}
	writeJSON(w, map[string]any{
		"ingestRunning": vm.Running,
		"stale":         vm.Stale,
		"linesRead":     stats.LinesRead,
		"alerts":        stats.Alerts,
		"written":       stats.Written,
		"parseErrors":   stats.ParseErrors,
		"lastLineAt":    isoOrEmpty(stats.LastLineAt),
		"lastAlertAt":   isoOrEmpty(stats.LastAlertAt),
		"lastError":     stats.LastError,
		"events":        counts.Events,
		"sources":       counts.Sources,
	})
}

func isoOrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}
