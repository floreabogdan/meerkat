package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"sort"
	"time"

	"github.com/floreabogdan/meerkat/internal/store"
)

// maxDetailEvents caps the raw event list on a source page. A source with
// 600 identical reputation alerts does not become more informative at 601.
const maxDetailEvents = 500

// eventVM is one stored event with its protocol context already decoded, so the
// template never parses JSON.
type eventVM struct {
	store.Event
	Context []kv
}

type kv struct{ Key, Value string }

// bucket is one column of the activity sparkline. It carries its own SVG
// geometry rather than a percentage, because the Content Security Policy
// forbids inline styles — a style="height:…" bar renders full-height in a real
// browser while looking fine in a server-side test. SVG x/y/width/height are
// plain attributes, not CSS, so they are allowed and exact.
type bucket struct {
	Start time.Time
	Count int64
	X     int // within the sparkViewW × sparkViewH viewBox
	Y     int
	W     int
	H     int
}

// The sparkline's viewBox. It is stretched to the container's width by
// preserveAspectRatio="none", so these are arbitrary working units.
const (
	sparkBuckets = 48
	sparkViewW   = 480
	sparkViewH   = 100
)

type sourceDetailVM struct {
	nav
	Source     store.Source
	Signatures []store.SourceSignature
	Ports      []store.SourcePort
	Events     []eventVM
	Actions    []store.Action

	// EventsShown is how many rows the table holds; StoredEvents is how many
	// this source has in the database right now. Source.EventCount is the
	// lifetime total, which can be larger than either once retention has run —
	// and the page says so rather than quietly disagreeing with itself.
	EventsShown  int
	StoredEvents int
	Retained     bool

	Timeline []bucket
	PeakBar  int64

	// CanBlock is false when nftably is not configured, so the page explains
	// itself rather than offering a button that always fails.
	CanBlock bool
	TTLs     []struct {
		Value string
		Label string
		Dur   time.Duration
	}

	Done string
	Err  string
}

func (s *Server) handleSourceDetail(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	// Validate before touching the database: the path segment is user input and
	// there is no reason a source key should ever be anything but an address.
	if _, err := netip.ParseAddr(ip); err != nil {
		http.NotFound(w, r)
		return
	}

	src, err := s.store.GetSource(ip)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.serverError(w, "get source", err)
		return
	}

	sigs, err := s.store.SignaturesForSource(ip)
	if err != nil {
		s.serverError(w, "signatures for source", err)
		return
	}
	ports, err := s.store.PortsForSource(ip)
	if err != nil {
		s.serverError(w, "ports for source", err)
		return
	}
	events, err := s.store.EventsForSource(ip, maxDetailEvents)
	if err != nil {
		s.serverError(w, "events for source", err)
		return
	}
	actions, err := s.store.ActionsForTarget(ip, 20)
	if err != nil {
		s.serverError(w, "actions for target", err)
		return
	}

	vm := sourceDetailVM{
		nav:          s.navFor(r, "sources"),
		Source:       src,
		Signatures:   sigs,
		Ports:        ports,
		Events:       decorateEvents(events),
		Actions:      actions,
		EventsShown:  len(events),
		StoredEvents: len(events),
		CanBlock:     s.triage.CanBlock(),
		TTLs:         blockTTLs,
		Done:         r.URL.Query().Get("done"),
		Err:          r.URL.Query().Get("err"),
	}
	// The rollup outliving its events is by design, not drift — say which number
	// is which so nobody has to guess.
	vm.Retained = src.EventCount > int64(len(events))
	vm.Timeline, vm.PeakBar = activityBuckets(events)

	render(w, s.log, "source.html", vm)
}

// decorateEvents decodes each event's protocol-context blob into ordered pairs
// the template can render directly.
func decorateEvents(events []store.Event) []eventVM {
	out := make([]eventVM, 0, len(events))
	for _, e := range events {
		vm := eventVM{Event: e}
		if e.Extra != "" {
			var m map[string]any
			if err := json.Unmarshal([]byte(e.Extra), &m); err == nil {
				keys := make([]string, 0, len(m))
				for k := range m {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					vm.Context = append(vm.Context, kv{Key: contextLabel(k), Value: toString(m[k])})
				}
			}
		}
		out = append(out, vm)
	}
	return out
}

var contextLabels = map[string]string{
	"http_host": "Host", "http_url": "URL", "user_agent": "User-Agent",
	"http_method": "Method", "http_status": "Status",
	"tls_sni": "TLS SNI", "dns_rrname": "DNS name", "ssh_client": "SSH client",
}

func contextLabel(key string) string {
	if l, ok := contextLabels[key]; ok {
		return l
	}
	return key
}

func toString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return itoa(int(t))
	case nil:
		return ""
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return ""
		}
		return string(b)
	}
}

// activityBuckets turns an event list into equal time buckets spanning first to
// last, with each bucket's bar geometry precomputed. Returns the buckets and the
// tallest count, so the template does no arithmetic at all.
func activityBuckets(events []store.Event) ([]bucket, int64) {
	if len(events) < 2 {
		return nil, 0
	}
	// Events arrive newest-first.
	last, first := events[0].Ts, events[len(events)-1].Ts
	span := last.Sub(first)
	if span <= 0 {
		return nil, 0
	}
	step := span / sparkBuckets
	if step <= 0 {
		return nil, 0
	}

	buckets := make([]bucket, sparkBuckets)
	for i := range buckets {
		buckets[i] = bucket{Start: first.Add(time.Duration(i) * step)}
	}
	var peak int64
	for _, e := range events {
		i := int(e.Ts.Sub(first) / step)
		i = min(max(i, 0), sparkBuckets-1)
		buckets[i].Count++
		peak = max(peak, buckets[i].Count)
	}

	slot := sparkViewW / sparkBuckets
	for i := range buckets {
		h := 0
		if peak > 0 {
			h = int(buckets[i].Count * sparkViewH / peak)
		}
		// A bucket with any activity gets at least one unit, so a quiet period
		// still reads as "something happened" rather than as a gap.
		if h == 0 && buckets[i].Count > 0 {
			h = 1
		}
		buckets[i].X = i * slot
		buckets[i].W = slot - 1 // a 1-unit gutter between bars
		buckets[i].H = h
		buckets[i].Y = sparkViewH - h
	}
	return buckets, peak
}
