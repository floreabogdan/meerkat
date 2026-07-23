package web

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/floreabogdan/meerkat/internal/store"
)

// sources.go serves the home page: the list of source addresses.
//
// It is a list of sources rather than a list of events on purpose. edge1 produced
// 891 alerts in four minutes from a few dozen addresses, 68.8% of them one
// reputation rule saying the same thing about the same hosts. Paging through
// that as rows is the thing meerkat exists to stop doing. Rolled up per source,
// the same data is a few dozen rows, each one a decision: block, acknowledge,
// allowlist, or ignore.

// defaultPageSize is how many sources one page shows. Large enough to see the
// shape of an incident, small enough to render fast on a router's CPU.
const defaultPageSize = 100

// timeWindow is one entry in the "last N" filter.
type timeWindow struct {
	Value string
	Label string
	Dur   time.Duration
}

var timeWindows = []timeWindow{
	{"", "Any time", 0},
	{"15m", "Last 15 minutes", 15 * time.Minute},
	{"1h", "Last hour", time.Hour},
	{"24h", "Last 24 hours", 24 * time.Hour},
	{"7d", "Last 7 days", 7 * 24 * time.Hour},
}

func windowByValue(v string) (timeWindow, bool) {
	for _, w := range timeWindows {
		if w.Value == v {
			return w, true
		}
	}
	return timeWindow{}, false
}

// tableColumns are the sources table's headers, in display order. Each is
// sortable; the last column (State) is not, and is rendered by the template.
var tableColumns = []struct {
	Key     string // matches store.SortColumn
	Label   string
	Numeric bool
	// AscFirst columns start ascending when first clicked. Only the address
	// does: for every count and timestamp, "biggest/most recent first" is what
	// someone opening this page during an incident wants.
	AscFirst bool
}{
	{Key: "ip", Label: "Source", AscFirst: true},
	{Key: "", Label: "Where"}, // not sortable — rendered from several columns
	{Key: "events", Label: "Alerts", Numeric: true},
	{Key: "sigs", Label: "Sigs", Numeric: true},
	{Key: "ports", Label: "Ports", Numeric: true},
	{Key: "severity", Label: "Worst"},
	{Key: "first_seen", Label: "First seen"},
	{Key: "last_seen", Label: "Last seen"},
}

// column is a rendered table header: its label, the link that sorts by it, and
// whether it is the one currently in effect.
type column struct {
	Label   string
	URL     string
	Active  bool
	Desc    bool
	Numeric bool
}

type sourcesVM struct {
	nav
	Counts  store.Counts
	Sources []store.Source
	Total   int64
	Shown   int

	// The filter bar's current state, echoed back so the form stays populated.
	Query       string
	Country     string
	ASN         string
	State       string
	Port        string
	SID         string
	MaxSeverity int
	Window      string
	MinEvents   int64
	Sort        string
	Desc        bool

	// Facets fill the dropdowns.
	Countries []store.Facet
	ASNs      []store.Facet
	Ports     []store.Facet

	// TopSignatures is the "what is actually making this noise" card. On real
	// data a handful of rules account for nearly all of it, and seeing that is
	// what turns a flood into a decision.
	TopSignatures []store.Signature
	SigTotal      int64

	Windows []timeWindow
	Columns []column
	Pager   pager

	Filtered bool
	Done     string
	Err      string

	// CanBlock gates the bulk block buttons; SelfURL is where a bulk action
	// returns to, so the operator keeps their filter and page.
	CanBlock bool
	SelfURL  string
	TTLs     []struct {
		Value string
		Label string
		Dur   time.Duration
	}

	// Ingest health, so an empty table is never ambiguous: no sources because
	// nothing is attacking, or no sources because nothing is being read?
	Ingest ingestVM
}

func (s *Server) handleSources(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	filter := store.SourceFilter{
		Query:       strings.TrimSpace(q.Get("q")),
		Country:     strings.TrimSpace(q.Get("country")),
		State:       strings.TrimSpace(q.Get("state")),
		MaxSeverity: intParam(r, "severity", 0),
		MinEvents:   int64Param(r, "min_events", 0),
		Sort:        q.Get("sort"),
		Limit:       defaultPageSize,
	}

	// Parse the numeric filters leniently: a stray value should empty the table
	// with the box still showing what was typed, not 400 the page.
	if v := strings.TrimSpace(q.Get("asn")); v != "" {
		if n, err := strconv.ParseUint(strings.TrimPrefix(strings.ToUpper(v), "AS"), 10, 32); err == nil {
			filter.ASN = uint32(n)
		}
	}
	if v := strings.TrimSpace(q.Get("port")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			filter.Port = n
		}
	}
	if v := strings.TrimSpace(q.Get("sid")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			filter.SID = n
		}
	}
	if !store.ValidState(filter.State) {
		filter.State = ""
	}
	if filter.MaxSeverity < 1 || filter.MaxSeverity > 3 {
		filter.MaxSeverity = 0
	}

	windowValue := q.Get("window")
	win, ok := windowByValue(windowValue)
	if !ok {
		windowValue, win = "", timeWindows[0]
	}
	if win.Dur > 0 {
		filter.Since = time.Now().Add(-win.Dur)
	}

	// Sort: default to the most recently active, descending, which is what an
	// operator wants when they open the page during an incident.
	if _, ok := store.SortColumn(filter.Sort); !ok {
		filter.Sort = "last_seen"
	}
	filter.Desc = q.Get("dir") != "asc"

	size := intParam(r, "size", defaultPageSize)
	if !validPageSize(size) {
		size = defaultPageSize
	}
	page := max(intParam(r, "page", 1), 1)
	filter.Limit = size
	filter.Offset = (page - 1) * size

	sources, total, err := s.store.ListSources(filter)
	if err != nil {
		s.serverError(w, "list sources", err)
		return
	}
	counts, err := s.store.Summary()
	if err != nil {
		s.serverError(w, "summary", err)
		return
	}
	countries, err := s.store.CountryFacets(60)
	if err != nil {
		s.serverError(w, "country facets", err)
		return
	}
	asns, err := s.store.ASNFacets(60)
	if err != nil {
		s.serverError(w, "asn facets", err)
		return
	}
	ports, err := s.store.PortFacets(40)
	if err != nil {
		s.serverError(w, "port facets", err)
		return
	}
	topSigs, err := s.store.TopSignatures(6)
	if err != nil {
		s.serverError(w, "top signatures", err)
		return
	}

	vm := sourcesVM{
		nav:           s.navFor(r, "sources"),
		Counts:        counts,
		Sources:       sources,
		Total:         total,
		Shown:         len(sources),
		Query:         filter.Query,
		Country:       filter.Country,
		State:         filter.State,
		MaxSeverity:   filter.MaxSeverity,
		MinEvents:     filter.MinEvents,
		Window:        windowValue,
		Sort:          filter.Sort,
		Desc:          filter.Desc,
		Countries:     countries,
		ASNs:          asns,
		Ports:         ports,
		TopSignatures: topSigs,
		// max(…, 1) because <progress max="0"> is invalid and renders as an
		// indeterminate spinner. Zero is reachable: retention can prune every
		// event while the signature rollups survive.
		SigTotal: max(counts.Events, 1),
		Windows:  timeWindows,
		Columns:  buildColumns(q, filter.Sort, filter.Desc),
		Pager:    buildPager(r, sourcesPath, page, size, total, "source"),
		Err:      q.Get("err"),
		Ingest:   s.ingestVM(),
	}
	// Echo the numeric filters back as they were typed, not as parsed, so a
	// typo is visible in the box rather than silently dropped.
	vm.ASN = strings.TrimSpace(q.Get("asn"))
	vm.Port = strings.TrimSpace(q.Get("port"))
	vm.SID = strings.TrimSpace(q.Get("sid"))
	vm.Filtered = vm.Query != "" || vm.Country != "" || vm.ASN != "" || vm.State != "" ||
		vm.Port != "" || vm.SID != "" || vm.MaxSeverity != 0 || vm.Window != "" || vm.MinEvents != 0

	render(w, s.log, "sources.html", vm)
}

// buildColumns renders the table's headers with the link that sorts by each.
// Clicking the column already in effect flips its direction; clicking any other
// switches to it in its natural starting direction.
func buildColumns(base url.Values, currentSort string, currentDesc bool) []column {
	out := make([]column, 0, len(tableColumns))
	for _, c := range tableColumns {
		if c.Key == "" { // a display-only column, with nothing to sort on
			out = append(out, column{Label: c.Label, Numeric: c.Numeric})
			continue
		}
		active := c.Key == currentSort
		desc := !c.AscFirst
		if active {
			desc = !currentDesc
		}
		out = append(out, column{
			Label:   c.Label,
			URL:     sortURL(base, c.Key, desc),
			Active:  active,
			Desc:    currentDesc,
			Numeric: c.Numeric,
		})
	}
	return out
}

// sortURL rewrites the current query string to sort by col, dropping the page
// number (a re-sort belongs on page one) while keeping every filter.
func sortURL(base url.Values, col string, desc bool) string {
	q := url.Values{}
	for k, v := range base {
		if k != "sort" && k != "dir" && k != "page" {
			q[k] = v
		}
	}
	q.Set("sort", col)
	if !desc {
		q.Set("dir", "asc")
	}
	return sourcesPath + "?" + q.Encode()
}
