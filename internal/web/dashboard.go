package web

import (
	"net/http"
	"time"

	"github.com/floreabogdan/meerkat/internal/store"
)

// dashboard.go is the overview: what the sensor is seeing, in aggregate.
//
// It is deliberately separate from /sources. The dashboard answers "what is
// going on" — volume over time, which rules are loud, which countries and ports
// dominate, is anything actually being blocked. The sources list answers "what
// do I do about it", and is a working surface: filter, sort, page, open one,
// act. Mixing the two put a filter bar under a set of summary tiles and made
// both worse.
//
// The rollup principle is unchanged and still the point of the product: nothing
// here is a list of events. Every number on this page comes from the per-source
// and per-signature rollups.

// activityChart is the 24-hour volume chart, pre-computed into SVG geometry for
// the same reason the source sparkline is: the CSP forbids inline styles, so
// bar heights travel as SVG attributes rather than style="height:%".
const (
	chartHours = 24
	chartViewW = 480
	chartViewH = 100
)

type chartBar struct {
	Start time.Time
	Count int64
	X, Y  int
	W, H  int
}

type dashboardVM struct {
	nav
	Counts store.Counts
	Ingest ingestVM
	Ship   shipVM

	Chart     []chartBar
	ChartPeak int64
	ChartFrom time.Time
	ChartTo   time.Time

	TopSignatures []store.Signature
	SigTotal      int64
	Categories    []store.CategoryCount
	CategoryTotal int64
	Countries     []store.Facet
	Ports         []store.Facet
	Busiest       []store.Source

	Retention int
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	counts, err := s.store.Summary()
	if err != nil {
		s.serverError(w, "summary", err)
		return
	}
	hourly, err := s.store.HourlyActivity(chartHours)
	if err != nil {
		s.serverError(w, "hourly activity", err)
		return
	}
	sigs, err := s.store.TopSignatures(6)
	if err != nil {
		s.serverError(w, "top signatures", err)
		return
	}
	cats, err := s.store.CategoryBreakdown(6)
	if err != nil {
		s.serverError(w, "category breakdown", err)
		return
	}
	countries, err := s.store.CountryFacets(8)
	if err != nil {
		s.serverError(w, "country facets", err)
		return
	}
	ports, err := s.store.PortFacets(8)
	if err != nil {
		s.serverError(w, "port facets", err)
		return
	}
	busiest, err := s.store.TopSources(8)
	if err != nil {
		s.serverError(w, "top sources", err)
		return
	}

	vm := dashboardVM{
		nav:           s.navFor(r, "dashboard"),
		Counts:        counts,
		Ingest:        s.ingestVM(),
		Ship:          s.shipVM(),
		TopSignatures: sigs,
		SigTotal:      max(counts.Events, 1),
		Categories:    cats,
		Countries:     countries,
		Ports:         ports,
		Busiest:       busiest,
	}
	for _, c := range cats {
		vm.CategoryTotal += c.Hits
	}
	vm.CategoryTotal = max(vm.CategoryTotal, 1)
	vm.Chart, vm.ChartPeak = chartBars(hourly)
	if len(hourly) > 0 {
		vm.ChartFrom, vm.ChartTo = hourly[0].Start, hourly[len(hourly)-1].Start
	}
	if st, ok, err := s.store.GetSettings(); err == nil && ok {
		vm.Retention = st.RetentionDays
	}

	render(w, s.log, "dashboard.html", vm)
}

// chartBars turns hourly counts into bar geometry, returning the bars and the
// tallest count so the template does no arithmetic.
func chartBars(hours []store.HourBucket) ([]chartBar, int64) {
	if len(hours) == 0 {
		return nil, 0
	}
	var peak int64
	for _, h := range hours {
		peak = max(peak, h.Count)
	}

	slot := chartViewW / len(hours)
	out := make([]chartBar, 0, len(hours))
	for i, h := range hours {
		height := 0
		if peak > 0 {
			height = int(h.Count * chartViewH / peak)
		}
		// An hour with any activity gets at least one unit, so a quiet stretch
		// reads as "something happened" rather than as a gap.
		if height == 0 && h.Count > 0 {
			height = 1
		}
		out = append(out, chartBar{
			Start: h.Start, Count: h.Count,
			X: i * slot, W: slot - 1, H: height, Y: chartViewH - height,
		})
	}
	return out, peak
}
