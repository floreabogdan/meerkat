package web

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/floreabogdan/meerkat/internal/rules"
	"github.com/floreabogdan/meerkat/internal/store"
)

// rules.go is the ruleset side of the console: what Suricata has installed,
// what the operator has decided about it, and whether the sensor agrees.
//
// The page is built around a join the sensor cannot make for itself. Suricata
// knows it has 52,000 rules; meerkat knows which of them have actually fired
// and how often. Sorting the catalogue by observed volume turns "which of these
// should I turn off" from a guess into a reading — and on edge1 the answer was
// visible immediately: two reputation rules produced 85% of everything.
//
// Two things are deliberately absent. There is no control that makes Suricata
// drop, because blocking belongs to nftables here. And nothing on this page
// claims a change has taken effect: an apply is a request to a privileged step,
// and what the page reports afterwards comes from re-reading the built ruleset.

// rulePageSize is how many catalogue rows one page shows.
const rulePageSize = 50

// autoBlockTTLs are the durations offered for "always block". Unlike a manual
// block, this one fires without anybody watching, so an indefinite auto-block
// is offered but not the default.
var autoBlockTTLs = []struct {
	Value string
	Label string
	Secs  int
}{
	{"1h", "1 hour", 3600},
	{"24h", "24 hours", 86400},
	{"7d", "7 days", 604800},
	{"30d", "30 days", 2592000},
	{"", "Until I unblock it", 0},
}

func autoBlockSecs(v string) int {
	for _, t := range autoBlockTTLs {
		if t.Value == v {
			return t.Secs
		}
	}
	return 0
}

// severityChoices are what a severity override can be set to. Suricata's scale
// runs 1 (worst) to 4, and meerkat keeps that direction everywhere.
var severityChoices = []struct {
	Value int
	Label string
}{
	{0, "Leave as Suricata reports it"},
	{1, "1 — severe"},
	{2, "2 — significant"},
	{3, "3 — minor"},
	{4, "4 — noise"},
}

type rulesVM struct {
	nav
	Tab    string
	Status rules.Status
	// Available is false when meerkat has no rules manager at all — a console
	// reading someone else's database, or a build without a sensor.
	Available bool

	Categories []store.RuleCategory
	// AllCategories fills the catalogue tab's category select. It is the same
	// list as Categories, loaded on the other tabs too so the filter can offer
	// real choices rather than a free-text box.
	AllCategories []store.RuleCategory
	Rules         []store.Rule
	Drifts        []rules.Drift
	Runs          []store.RuleRun
	Pager         pager

	// The filter bar's state, echoed back.
	Query    string
	Category string
	State    string
	Policy   string
	Firing   bool
	Sort     string
	Desc     bool
	Columns  []column
	ClearURL string
	// BackURL is where a form on this page returns to, so setting a policy on
	// page 7 of a filtered catalogue does not dump the operator back at page 1
	// of everything.
	BackURL  string
	Filtered bool
	Total    int
	TTLs     []struct {
		Value string
		Label string
		Secs  int
	}
	Severities []struct {
		Value int
		Label string
	}

	Done string
	Err  string
}

var ruleColumns = []struct {
	Key     string
	Label   string
	Numeric bool
}{
	{Key: "sid", Label: "SID"},
	{Key: "msg", Label: "Rule"},
	{Key: "category", Label: "Category"},
	{Key: "hits", Label: "Alerts", Numeric: true},
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	vm := rulesVM{
		nav:        s.navFor(r, "rules"),
		Tab:        tabParam(r, "categories", "catalogue", "changes", "history"),
		Available:  s.rules != nil,
		TTLs:       autoBlockTTLs,
		Severities: severityChoices,
		Done:       r.URL.Query().Get("done"),
		Err:        r.URL.Query().Get("err"),
	}
	if !vm.Available {
		render(w, s.log, "rules.html", vm)
		return
	}

	status, err := s.rules.Status()
	if err != nil {
		s.serverError(w, "rules status", err)
		return
	}
	vm.Status = status
	// Where the forms on this page come back to. Built from the request rather
	// than hard-coded so a decision made on page 7 of a filtered catalogue
	// returns to page 7 of that filter.
	if back := r.URL.RequestURI(); isLocalPath(back) {
		vm.BackURL = back
	} else {
		vm.BackURL = rulesPath
	}

	switch vm.Tab {
	case "categories":
		cats, err := s.store.RuleCategories()
		if err != nil {
			s.serverError(w, "rule categories", err)
			return
		}
		vm.Categories = cats
	case "catalogue":
		if err := s.fillCatalogue(r, &vm); err != nil {
			s.serverError(w, "list rules", err)
			return
		}
	case "changes":
		drifts, err := s.rules.Drifts()
		if err != nil {
			s.serverError(w, "rule drifts", err)
			return
		}
		vm.Drifts = drifts
	case "history":
		runs, err := s.store.RuleRuns(50)
		if err != nil {
			s.serverError(w, "rule runs", err)
			return
		}
		vm.Runs = runs
	}
	render(w, s.log, "rules.html", vm)
}

func (s *Server) fillCatalogue(r *http.Request, vm *rulesVM) error {
	q := r.URL.Query()
	vm.Query = strings.TrimSpace(q.Get("q"))
	vm.Category = q.Get("category")
	vm.State = q.Get("state")
	vm.Policy = q.Get("policy")
	vm.Firing = q.Get("firing") == "1"
	vm.Sort = q.Get("sort")
	// Loudest first is the default, and descending is what "loudest" means.
	vm.Desc = q.Get("dir") != "asc"

	page := max(intParam(r, "page", 1), 1)
	size := intParam(r, "size", rulePageSize)
	if !validPageSize(size) {
		size = rulePageSize
	}

	list, total, err := s.store.ListRules(store.RuleFilter{
		Query: vm.Query, Category: vm.Category, State: vm.State,
		Policy: vm.Policy, Firing: vm.Firing,
		Sort: vm.Sort, Desc: vm.Desc, Page: page, PerPage: size,
	})
	if err != nil {
		return err
	}
	vm.Rules, vm.Total = list, total
	vm.Pager = buildPager(r, rulesPath, page, size, int64(total), "rule")
	vm.Columns = ruleColumnLinks(r, vm.Sort, vm.Desc)
	vm.ClearURL = rulesPath + "?tab=catalogue"
	vm.Filtered = vm.Query != "" || vm.Category != "" || vm.State != "" || vm.Policy != "" || vm.Firing

	cats, err := s.store.RuleCategories()
	if err != nil {
		return err
	}
	vm.AllCategories = cats
	return nil
}

func ruleColumnLinks(r *http.Request, sort string, desc bool) []column {
	if sort == "" {
		sort = "hits"
	}
	out := make([]column, 0, len(ruleColumns))
	for _, c := range ruleColumns {
		q := r.URL.Query()
		q.Set("tab", "catalogue")
		q.Set("sort", c.Key)
		q.Del("page")
		active := c.Key == sort
		// Clicking the active column flips it; clicking a new one starts with
		// the direction that column is actually useful in.
		switch {
		case active && desc:
			q.Set("dir", "asc")
		case active:
			q.Set("dir", "desc")
		case c.Numeric:
			q.Set("dir", "desc")
		default:
			q.Set("dir", "asc")
		}
		out = append(out, column{
			Label: c.Label, URL: rulesPath + "?" + q.Encode(),
			Active: active, Desc: active && desc, Numeric: c.Numeric,
		})
	}
	return out
}

// ruleDetailVM is one rule, everything meerkat knows about it, and the sources
// that have tripped it.
type ruleDetailVM struct {
	nav
	Rule      store.Rule
	Signature store.Signature
	HasStats  bool
	Sources   []store.Source
	Status    rules.Status
	Available bool
	TTLs      []struct {
		Value string
		Label string
		Secs  int
	}
	Severities []struct {
		Value int
		Label string
	}
	Done string
	Err  string
}

func (s *Server) handleRuleDetail(w http.ResponseWriter, r *http.Request) {
	sid, err := strconv.Atoi(r.PathValue("sid"))
	if err != nil || sid <= 0 {
		http.NotFound(w, r)
		return
	}
	if s.rules == nil {
		http.NotFound(w, r)
		return
	}
	rule, err := s.store.GetRule(sid)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.serverError(w, "get rule", err)
		return
	}
	status, err := s.rules.Status()
	if err != nil {
		s.serverError(w, "rules status", err)
		return
	}
	// Which sources have tripped it — the other half of the question "should I
	// keep this rule on". A rule firing on 400 addresses is a reputation feed;
	// one firing on two is worth reading.
	sources, _, err := s.store.ListSources(store.SourceFilter{
		SID: sid, Sort: "events", Desc: true, Limit: 25,
	})
	if err != nil {
		s.serverError(w, "sources for signature", err)
		return
	}
	render(w, s.log, "rule.html", ruleDetailVM{
		nav: s.navFor(r, "rules"), Rule: rule, Status: status, Available: true,
		Sources: sources, TTLs: autoBlockTTLs, Severities: severityChoices,
		Done: r.URL.Query().Get("done"), Err: r.URL.Query().Get("err"),
	})
}

// handleRulePolicy records a decision about a rule or a category.
//
// It writes the policy and nothing else. Nothing here touches the sensor: a
// decision and its application are separate steps on purpose, so an operator
// can turn off six noisy rules and pay the cost of rebuilding the ruleset once.
// The page then says how many changes are waiting.
func (s *Server) handleRulePolicy(w http.ResponseWriter, r *http.Request) {
	back := rulesPath
	if err := r.ParseForm(); err != nil {
		s.ruleRedirect(w, r, back, "", "could not read the form")
		return
	}
	if b := r.FormValue("back"); isLocalPath(b) {
		back = b
	}
	if s.rules == nil {
		s.ruleRedirect(w, r, back, "", "rule management is not available on this console")
		return
	}

	scope := r.FormValue("scope")
	key := strings.TrimSpace(r.FormValue("key"))
	p := store.RulePolicy{
		Scope:        scope,
		Key:          key,
		State:        r.FormValue("state"),
		AutoBlock:    r.FormValue("autoblock") == "1",
		AutoBlockTTL: autoBlockSecs(r.FormValue("autoblock_ttl")),
		Severity:     formInt(r, "severity", 0, 0, 4),
		Note:         strings.TrimSpace(r.FormValue("note")),
		Actor:        s.currentUser(r).Username,
	}

	// "Always block" without the master switch on is a decision that would
	// silently do nothing. Record it, and say so, rather than either refusing
	// the click or letting the operator believe it is armed.
	var warning string
	if p.AutoBlock {
		if settings, ok, err := s.store.GetSettings(); err == nil && ok && !settings.AutoBlockEnabled {
			warning = " — but blocking on sight is switched off under Settings → Suricata, so nothing will act on it yet"
		}
	}

	if err := s.store.SetRulePolicy(p); err != nil {
		s.ruleRedirect(w, r, back, "", err.Error())
		return
	}
	s.audit(r, store.AuditSourceChange, "rule policy set for "+scope+" "+key)
	_ = s.store.RecordAction(store.Action{
		Actor: p.Actor, Action: store.ActionMute, Target: scope + ":" + key,
		Reason: policySummary(p), Result: "recorded", OK: true,
	})
	s.ruleRedirect(w, r, back, describePolicy(scope, key, p)+warning, "")
}

func policySummary(p store.RulePolicy) string {
	var parts []string
	if p.State != store.RuleStateDefault {
		parts = append(parts, p.State)
	}
	if p.AutoBlock {
		parts = append(parts, "block on sight")
	}
	if p.Severity > 0 {
		parts = append(parts, "severity "+strconv.Itoa(p.Severity))
	}
	if len(parts) == 0 {
		parts = append(parts, "cleared")
	}
	if p.Note != "" {
		return strings.Join(parts, ", ") + " — " + p.Note
	}
	return strings.Join(parts, ", ")
}

func describePolicy(scope, key string, p store.RulePolicy) string {
	what := "rule " + key
	if scope == store.RuleScopeCategory {
		what = key
	}
	switch {
	case !p.Opinionated():
		return what + " is back to the ruleset's default"
	case p.State == store.RuleStateDisabled:
		return what + " will be disabled at the next apply"
	case p.State == store.RuleStateEnabled:
		return what + " will be enabled at the next apply"
	case p.AutoBlock:
		return what + " will block its source on sight"
	default:
		return what + " updated"
	}
}

// handleRulesApply asks for the staged policy to be pushed to the sensor.
//
// meerkat's own account cannot do this — it cannot write /etc/suricata, run
// suricata-update, or open Suricata's root-owned control socket, and that is
// the point. What this handler does is render the filter files into meerkat's
// state directory and leave a request; a root oneshot does the rest and writes
// back what happened.
func (s *Server) handleRulesApply(w http.ResponseWriter, r *http.Request) {
	back := rulesPath
	if err := r.ParseForm(); err != nil {
		s.ruleRedirect(w, r, back, "", "could not read the form")
		return
	}
	if b := r.FormValue("back"); isLocalPath(b) {
		back = b
	}
	if s.rules == nil {
		s.ruleRedirect(w, r, back, "", "rule management is not available on this console")
		return
	}

	reason := strings.TrimSpace(r.FormValue("reason"))
	if reason == "" {
		reason = "applied from the meerkat console"
	}
	// A plain apply rebuilds from the cached ruleset; "fetch" also pulls a fresh
	// one from the configured sources.
	fetch := r.FormValue("fetch") == "1"

	err := s.rules.Stage(s.currentUser(r).Username, reason, !fetch)
	if errors.Is(err, rules.ErrApplyPending) {
		s.ruleRedirect(w, r, back, "", "a ruleset change is already being applied — wait for it to finish")
		return
	}
	if err != nil {
		s.ruleRedirect(w, r, back, "", err.Error())
		return
	}
	s.audit(r, store.AuditSettings, "requested a suricata ruleset apply: "+reason)

	msg := "Applying — suricata-update is rebuilding the ruleset. This takes a few minutes; the page will show the result."
	if fetch {
		msg = "Fetching a fresh ruleset and rebuilding. This takes a few minutes; the page will show the result."
	}
	s.ruleRedirect(w, r, back, msg, "")
}

func (s *Server) ruleRedirect(w http.ResponseWriter, r *http.Request, back, msg, errMsg string) {
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
