package web

import (
	"net/http"
	"net/url"
	"strconv"
)

// pager.go renders a numbered pager for a server-side paged table.
//
// The sources list pages on the server, not in the browser, because the row set
// is unbounded: a week of a busy sensor is tens of thousands of source rows, and
// shipping all of them so JavaScript can hide most is how a console becomes
// unusable on the router it is meant to be watching. Every other table on the
// site is bounded by construction (one source's signatures, one page of alerts)
// and pages client-side via paginate.js instead.

// pageSizes are the row counts the operator can choose between.
var pageSizes = []int{25, 50, 100, 250}

func validPageSize(n int) bool {
	for _, s := range pageSizes {
		if s == n {
			return true
		}
	}
	return false
}

// pagerPage is one entry in the numbered strip: either a page link or a gap
// marker standing in for an elided run.
type pagerPage struct {
	Num     int
	URL     string
	Current bool
	Gap     bool
}

// pager is everything the "pager" template partial needs.
type pager struct {
	Summary   string // "1–100 of 4,812 sources"
	Pages     []pagerPage
	PrevURL   string
	NextURL   string
	HasPrev   bool
	HasNext   bool
	Sizes     []int
	Size      int
	SizeURLs  map[int]string
	Show      bool // false when everything fits on one page
	TotalRows int64
}

// buildPager works out the numbered strip for the current request. base is the
// path every link is built on and noun is what is being counted ("source"), for
// the summary line.
//
// base is passed in rather than taken from r.URL.Path because pages that render
// links to another list — the dashboard links into /sources — would otherwise
// build them against themselves.
func buildPager(r *http.Request, base string, page, size int, total int64, noun string) pager {
	pages := int((total + int64(size) - 1) / int64(size))
	if pages < 1 {
		pages = 1
	}
	page = min(max(page, 1), pages)

	first := int64((page-1)*size) + 1
	last := min(int64(page*size), total)
	if total == 0 {
		first = 0
	}

	p := pager{
		Summary:   humanNumber(first) + "–" + humanNumber(last) + " of " + humanNumber(total) + " " + plural(total, noun),
		HasPrev:   page > 1,
		HasNext:   page < pages,
		PrevURL:   pagedURL(r, base, page-1, size),
		NextURL:   pagedURL(r, base, page+1, size),
		Sizes:     pageSizes,
		Size:      size,
		SizeURLs:  map[int]string{},
		Show:      pages > 1 || total > int64(pageSizes[0]),
		TotalRows: total,
	}
	for _, s := range pageSizes {
		// Changing the page size returns to page one: keeping the number would
		// land the operator somewhere unrelated to what they were reading.
		p.SizeURLs[s] = pagedURL(r, base, 1, s)
	}
	for _, n := range pageWindow(page, pages) {
		if n == 0 {
			p.Pages = append(p.Pages, pagerPage{Gap: true})
			continue
		}
		p.Pages = append(p.Pages, pagerPage{Num: n, URL: pagedURL(r, base, n, size), Current: n == page})
	}
	return p
}

// pageWindow is a compact page list: first, last, and the pages either side of
// the current one, with 0 standing in for an elided run (1 … 4 5 6 … 20).
func pageWindow(current, pages int) []int {
	if pages <= 7 {
		out := make([]int, 0, pages)
		for i := 1; i <= pages; i++ {
			out = append(out, i)
		}
		return out
	}
	out := []int{1}
	lo, hi := max(2, current-1), min(pages-1, current+1)
	if lo > 2 {
		out = append(out, 0)
	}
	for i := lo; i <= hi; i++ {
		out = append(out, i)
	}
	if hi < pages-1 {
		out = append(out, 0)
	}
	return append(out, pages)
}

// pagedURL rewrites the current query string with a page number and size,
// preserving every filter and the sort.
func pagedURL(r *http.Request, base string, page, size int) string {
	q := r.URL.Query()
	if page <= 1 {
		q.Del("page")
	} else {
		q.Set("page", strconv.Itoa(page))
	}
	if size == defaultPageSize {
		q.Del("size")
	} else {
		q.Set("size", strconv.Itoa(size))
	}
	return withQuery(base, q)
}

// sourcesPath and rulesPath are the bases their list links are built on. They
// are constants rather than r.URL.Path so a link rendered on one page cannot
// accidentally point at that page instead of the list it names.
const (
	sourcesPath = "/sources"
	rulesPath   = "/rules"
)

func withQuery(base string, q url.Values) string {
	if len(q) == 0 {
		return base
	}
	return base + "?" + q.Encode()
}

func plural(n int64, noun string) string {
	if n == 1 {
		return noun
	}
	return noun + "s"
}
