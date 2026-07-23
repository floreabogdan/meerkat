package store

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// rules.go holds the ruleset catalogue and the operator's policy over it.
//
// Two tables, and the difference between them is the whole idea. `rules` is
// every signature installed on the sensor, rebuilt wholesale each time the
// ruleset changes. `rule_policy` is what somebody decided, and it must outlive
// that rebuild — a rule dropped from ET Open and reinstated six months later
// comes back muted, because muting it was a decision and the catalogue is only
// an observation.

// Rule scopes and states, mirroring internal/suricata so callers of the store
// do not have to import both.
const (
	RuleScopeSID      = "sid"
	RuleScopeCategory = "category"

	RuleStateDefault  = ""
	RuleStateEnabled  = "enabled"
	RuleStateDisabled = "disabled"
)

// Rule is one signature in the installed ruleset, with whatever meerkat knows
// about it from elsewhere joined on.
type Rule struct {
	SID       int
	GID       int
	Rev       int
	Action    string
	Proto     string
	Msg       string
	Category  string
	Classtype string
	Priority  int
	// ETSeverity is Emerging Threats' metadata rating, not Suricata's numeric
	// severity. Both exist; they are not the same axis and are never mixed.
	ETSeverity  string
	RuleCreated string
	RuleUpdated string
	// Enabled is the state in the built ruleset — the fact, as opposed to
	// Policy.State, which is the intent.
	Enabled bool

	// Hits and LastSeen come from the signatures table: how much this rule has
	// actually cost us. A catalogue without them makes the operator guess which
	// of 52,000 rules is the noisy one.
	Hits     int64
	LastSeen time.Time

	// Policy is the sid-scoped decision, if there is one.
	Policy RulePolicy
	// CategoryPolicy is the decision covering this rule's whole category, if
	// there is one. Filled in by ListRules so a row can explain why it is off
	// when nobody ever named it.
	CategoryPolicy RulePolicy
}

// RulePolicy is a decision about a rule or a category.
type RulePolicy struct {
	Scope string
	Key   string
	State string
	// AutoBlock pushes the source to nftably when this rule fires. It is not a
	// Suricata drop and never becomes one.
	AutoBlock    bool
	AutoBlockTTL int // seconds; 0 means until someone unblocks it
	// Severity overrides what meerkat records for this rule's alerts.
	// 0 = no override; 1 is worst.
	Severity  int
	Note      string
	Actor     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Set reports whether this is a real policy rather than a zero value.
func (p RulePolicy) Set() bool { return p.Scope != "" }

// Opinionated reports whether the policy says anything at all. A row can exist
// with everything cleared, and that is the same as having no policy.
func (p RulePolicy) Opinionated() bool {
	return p.State != RuleStateDefault || p.AutoBlock || p.Severity > 0
}

// ── indexing ─────────────────────────────────────────────────────────────

// RuleIndexStats is what an index pass changed.
type RuleIndexStats struct {
	Total   int
	Enabled int
	Added   int
	Removed int
}

// RuleIndexer rebuilds the catalogue from a scan of the rules file.
//
// It streams rather than taking a slice: the file is 45 MB and holds 68,000
// rules, and there is no reason to hold all of them in memory to write them to
// a table. Everything happens in one transaction, so a failure part-way leaves
// the previous catalogue intact rather than a half-updated one.
type RuleIndexer struct {
	tx     *sql.Tx
	stmt   *sql.Stmt
	pass   string
	before int
	stats  RuleIndexStats
}

// BeginRuleIndex starts an index pass.
func (s *Store) BeginRuleIndex() (*RuleIndexer, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("store: begin rule index: %w", err)
	}
	var before int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM rules`).Scan(&before); err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("store: count rules: %w", err)
	}
	stmt, err := tx.Prepare(`
		INSERT INTO rules (sid, gid, rev, action, proto, msg, category, classtype,
			priority, et_severity, rule_created, rule_updated, enabled, first_seen, seen_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(sid) DO UPDATE SET
			gid = excluded.gid, rev = excluded.rev, action = excluded.action,
			proto = excluded.proto, msg = excluded.msg, category = excluded.category,
			classtype = excluded.classtype, priority = excluded.priority,
			et_severity = excluded.et_severity, rule_created = excluded.rule_created,
			rule_updated = excluded.rule_updated, enabled = excluded.enabled,
			seen_at = excluded.seen_at`)
	if err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("store: prepare rule upsert: %w", err)
	}
	return &RuleIndexer{tx: tx, stmt: stmt, pass: now(), before: before}, nil
}

// Add records one rule.
func (ix *RuleIndexer) Add(r Rule) error {
	_, err := ix.stmt.Exec(r.SID, r.GID, r.Rev, r.Action, r.Proto, r.Msg, r.Category,
		r.Classtype, r.Priority, r.ETSeverity, r.RuleCreated, r.RuleUpdated,
		r.Enabled, ix.pass, ix.pass)
	if err != nil {
		return fmt.Errorf("store: index rule %d: %w", r.SID, err)
	}
	ix.stats.Total++
	if r.Enabled {
		ix.stats.Enabled++
	}
	return nil
}

// Commit deletes anything the pass did not see and finishes the transaction.
//
// The stale sweep is what makes a rule removed upstream disappear from the
// console instead of lingering forever as a rule the operator cannot find in
// the file. Its policy row survives it, deliberately.
func (ix *RuleIndexer) Commit() (RuleIndexStats, error) {
	res, err := ix.tx.Exec(`DELETE FROM rules WHERE seen_at <> ?`, ix.pass)
	if err != nil {
		_ = ix.tx.Rollback()
		return RuleIndexStats{}, fmt.Errorf("store: sweep stale rules: %w", err)
	}
	removed, _ := res.RowsAffected()
	ix.stats.Removed = int(removed)
	// Everything that survived plus everything written, minus what was there
	// before, is what is new.
	ix.stats.Added = ix.stats.Total - (ix.before - ix.stats.Removed)
	if ix.stats.Added < 0 {
		ix.stats.Added = 0
	}
	if err := ix.tx.Commit(); err != nil {
		return RuleIndexStats{}, fmt.Errorf("store: commit rule index: %w", err)
	}
	return ix.stats, nil
}

// Rollback abandons a pass.
func (ix *RuleIndexer) Rollback() { _ = ix.tx.Rollback() }

// RuleCounts is the headline: how big the installed ruleset is.
type RuleCounts struct {
	Total     int
	Enabled   int
	IndexedAt time.Time
}

// RuleCounts reports the size of the catalogue.
func (s *Store) RuleCounts() (RuleCounts, error) {
	var c RuleCounts
	var seen sql.NullString
	err := s.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(enabled), 0), MAX(seen_at) FROM rules`).
		Scan(&c.Total, &c.Enabled, &seen)
	if err != nil {
		return c, fmt.Errorf("store: rule counts: %w", err)
	}
	if seen.Valid {
		c.IndexedAt = ParseTime(seen.String)
	}
	return c, nil
}

// ── the catalogue ────────────────────────────────────────────────────────

// RuleFilter narrows the catalogue. 52,000 rules is not a list to read.
type RuleFilter struct {
	Query    string // matches the message, or an exact sid
	Category string
	// State filters on the built ruleset: "enabled" or "disabled".
	State string
	// Policy filters on the operator's decisions: "any", "autoblock",
	// "disabled", "enabled", "severity".
	Policy string
	// Firing keeps only rules that have actually produced an alert.
	Firing bool

	Sort    string // hits | sid | msg | category
	Desc    bool
	Page    int
	PerPage int
}

// ListRules returns one page of the catalogue and the total number of matches.
func (s *Store) ListRules(f RuleFilter) ([]Rule, int, error) {
	where, args := ruleWhere(f)

	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM rules r `+ruleJoins+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("store: count rules: %w", err)
	}

	perPage := f.PerPage
	if perPage <= 0 {
		perPage = 50
	}
	page := max(f.Page, 1)
	offset := (page - 1) * perPage

	query := `SELECT r.sid, r.gid, r.rev, r.action, r.proto, r.msg, r.category, r.classtype,
			r.priority, r.et_severity, r.rule_created, r.rule_updated, r.enabled,
			COALESCE(sg.hits, 0), COALESCE(sg.last_seen, ''),
			COALESCE(p.state, ''), COALESCE(p.autoblock, 0), COALESCE(p.autoblock_ttl, 0),
			COALESCE(p.severity, 0), COALESCE(p.note, ''), COALESCE(p.actor, ''),
			COALESCE(p.updated_at, '')
		FROM rules r ` + ruleJoins + where + ruleOrder(f) + ` LIMIT ? OFFSET ?`
	rows, err := s.db.Query(query, append(args, perPage, offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("store: list rules: %w", err)
	}
	defer rows.Close()

	var out []Rule
	for rows.Next() {
		var r Rule
		var lastSeen, policyUpdated string
		if err := rows.Scan(&r.SID, &r.GID, &r.Rev, &r.Action, &r.Proto, &r.Msg, &r.Category,
			&r.Classtype, &r.Priority, &r.ETSeverity, &r.RuleCreated, &r.RuleUpdated, &r.Enabled,
			&r.Hits, &lastSeen,
			&r.Policy.State, &r.Policy.AutoBlock, &r.Policy.AutoBlockTTL,
			&r.Policy.Severity, &r.Policy.Note, &r.Policy.Actor, &policyUpdated); err != nil {
			return nil, 0, fmt.Errorf("store: scan rule: %w", err)
		}
		r.LastSeen = ParseTime(lastSeen)
		if policyUpdated != "" {
			r.Policy.Scope, r.Policy.Key = RuleScopeSID, strconv.Itoa(r.SID)
			r.Policy.UpdatedAt = ParseTime(policyUpdated)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	// A rule can be off because its whole category is off. Attaching that here
	// is what lets a row say "disabled with ET CINS" instead of leaving the
	// operator wondering who turned it off.
	cats, err := s.RulePoliciesByScope(RuleScopeCategory)
	if err != nil {
		return nil, 0, err
	}
	for i := range out {
		if p, ok := cats[out[i].Category]; ok {
			out[i].CategoryPolicy = p
		}
	}
	return out, total, nil
}

// ruleJoins brings in what the rule has cost and what was decided about it.
const ruleJoins = `
	LEFT JOIN signatures sg ON sg.sid = r.sid
	LEFT JOIN rule_policy p ON p.scope = 'sid' AND p.key = CAST(r.sid AS TEXT) `

func ruleWhere(f RuleFilter) (string, []any) {
	var cond []string
	var args []any

	if q := strings.TrimSpace(f.Query); q != "" {
		if sid, err := strconv.Atoi(q); err == nil {
			cond = append(cond, `r.sid = ?`)
			args = append(args, sid)
		} else {
			cond = append(cond, `r.msg LIKE ? ESCAPE '\'`)
			args = append(args, "%"+escapeLike(q)+"%")
		}
	}
	if f.Category != "" {
		cond = append(cond, `r.category = ?`)
		args = append(args, f.Category)
	}
	switch f.State {
	case "enabled":
		cond = append(cond, `r.enabled = 1`)
	case "disabled":
		cond = append(cond, `r.enabled = 0`)
	}
	switch f.Policy {
	case "any":
		cond = append(cond, `(p.state <> '' OR p.autoblock = 1 OR p.severity > 0)`)
	case "autoblock":
		cond = append(cond, `p.autoblock = 1`)
	case "disabled":
		cond = append(cond, `p.state = 'disabled'`)
	case "enabled":
		cond = append(cond, `p.state = 'enabled'`)
	case "severity":
		cond = append(cond, `p.severity > 0`)
	}
	if f.Firing {
		cond = append(cond, `COALESCE(sg.hits, 0) > 0`)
	}
	if len(cond) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(cond, " AND "), args
}

// escapeLike neutralises the wildcards in a search term. Rule messages are full
// of underscores — ET's own categories are WEB_SPECIFIC_APPS, EXPLOIT_KIT — and
// an unescaped one is LIKE's "any single character", so searching for
// "USER_AGENTS" would quietly also match "USERXAGENTS".
func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

func ruleOrder(f RuleFilter) string {
	dir := " ASC"
	if f.Desc {
		dir = " DESC"
	}
	switch f.Sort {
	case "sid":
		return " ORDER BY r.sid" + dir
	case "msg":
		return " ORDER BY r.msg" + dir + ", r.sid"
	case "category":
		return " ORDER BY r.category" + dir + ", COALESCE(sg.hits, 0) DESC, r.sid"
	default:
		// Loudest first is the useful default: the question the catalogue exists
		// to answer is "what is generating all this", and the answer is at the
		// top of that sort.
		return " ORDER BY COALESCE(sg.hits, 0) DESC, r.sid ASC"
	}
}

// GetRule returns one rule by sid.
func (s *Store) GetRule(sid int) (Rule, error) {
	rules, _, err := s.ListRules(RuleFilter{Query: strconv.Itoa(sid), PerPage: 1})
	if err != nil {
		return Rule{}, err
	}
	if len(rules) == 0 {
		return Rule{}, ErrNotFound
	}
	return rules[0], nil
}

// RuleEnabledBySID reports, for each sid asked about, whether it is live in the
// built ruleset. A sid missing from the returned map is not in the catalogue at
// all — which is a different thing from being disabled, and is reported as
// such: a policy naming a rule the sensor does not have is worth saying out
// loud rather than showing as permanently pending.
func (s *Store) RuleEnabledBySID(sids []int) (map[int]bool, error) {
	out := make(map[int]bool, len(sids))
	if len(sids) == 0 {
		return out, nil
	}
	args := make([]any, len(sids))
	for i, sid := range sids {
		args[i] = sid
	}
	q := `SELECT sid, enabled FROM rules WHERE sid IN (?` + strings.Repeat(",?", len(sids)-1) + `)`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: rule enabled by sid: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var sid int
		var enabled bool
		if err := rows.Scan(&sid, &enabled); err != nil {
			return nil, err
		}
		out[sid] = enabled
	}
	return out, rows.Err()
}

// ── categories ───────────────────────────────────────────────────────────

// RuleCategory is one category with its size, its state and what it has cost.
type RuleCategory struct {
	Name     string
	Total    int
	Enabled  int
	Hits     int64
	Sources  int64
	LastSeen time.Time
	Policy   RulePolicy
}

// Disabled reports whether every rule in the category is off in the built
// ruleset — the fact, rather than the intent recorded in Policy.
func (c RuleCategory) Disabled() bool { return c.Total > 0 && c.Enabled == 0 }

// Partial reports whether the category is neither fully on nor fully off, which
// usually means suricata-update kept some rules alive for their flowbits.
func (c RuleCategory) Partial() bool { return c.Enabled > 0 && c.Enabled < c.Total }

// RuleCategories lists every category in the catalogue, noisiest first.
func (s *Store) RuleCategories() ([]RuleCategory, error) {
	rows, err := s.db.Query(`
		SELECT r.category, COUNT(*), COALESCE(SUM(r.enabled), 0),
			COALESCE(SUM(sg.hits), 0), COALESCE(SUM(sg.source_count), 0),
			COALESCE(MAX(sg.last_seen), '')
		FROM rules r LEFT JOIN signatures sg ON sg.sid = r.sid
		GROUP BY r.category
		ORDER BY COALESCE(SUM(sg.hits), 0) DESC, r.category ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: rule categories: %w", err)
	}
	defer rows.Close()

	var out []RuleCategory
	for rows.Next() {
		var c RuleCategory
		var last string
		if err := rows.Scan(&c.Name, &c.Total, &c.Enabled, &c.Hits, &c.Sources, &last); err != nil {
			return nil, fmt.Errorf("store: scan rule category: %w", err)
		}
		c.LastSeen = ParseTime(last)
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	policies, err := s.RulePoliciesByScope(RuleScopeCategory)
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Policy = policies[out[i].Name]
	}
	return out, nil
}

// ObservedCategories reports the message-prefix categories seen in actual
// alerts, loudest first. It reads the signatures table rather than the
// catalogue, so it still works before the ruleset has ever been indexed — and
// on a console pointed at an eve.json from another box, where there is no
// ruleset to index at all.
func (s *Store) ObservedCategories(limit int) ([]CategoryCount, error) {
	rows, err := s.db.Query(`
		SELECT COALESCE(NULLIF(rule_category, ''), 'uncategorised'), SUM(hits)
		FROM signatures GROUP BY rule_category
		ORDER BY SUM(hits) DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: observed categories: %w", err)
	}
	defer rows.Close()
	var out []CategoryCount
	for rows.Next() {
		var c CategoryCount
		if err := rows.Scan(&c.Category, &c.Hits); err != nil {
			return nil, fmt.Errorf("store: scan observed category: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// BackfillRuleCategories fills in the message-prefix category for signatures
// recorded before meerkat kept one. categoryOf is passed in so the store does
// not have to know how a rule message is parsed.
func (s *Store) BackfillRuleCategories(categoryOf func(string) string) (int, error) {
	rows, err := s.db.Query(`SELECT sid, signature FROM signatures WHERE rule_category = ''`)
	if err != nil {
		return 0, fmt.Errorf("store: read signatures to backfill: %w", err)
	}
	type pair struct {
		sid int
		cat string
	}
	var todo []pair
	for rows.Next() {
		var sid int
		var sig string
		if err := rows.Scan(&sid, &sig); err != nil {
			rows.Close()
			return 0, err
		}
		todo = append(todo, pair{sid, categoryOf(sig)})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(todo) == 0 {
		return 0, nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`UPDATE signatures SET rule_category = ? WHERE sid = ?`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()
	for _, p := range todo {
		if _, err := stmt.Exec(p.cat, p.sid); err != nil {
			return 0, fmt.Errorf("store: backfill rule category for %d: %w", p.sid, err)
		}
	}
	return len(todo), tx.Commit()
}

// ── policy ───────────────────────────────────────────────────────────────

// SetRulePolicy records a decision. Writing every field at once is deliberate:
// the UI edits one policy row through one form, and partial updates across
// several forms are how two settings quietly clobber each other.
func (s *Store) SetRulePolicy(p RulePolicy) error {
	switch p.Scope {
	case RuleScopeSID, RuleScopeCategory:
	default:
		return fmt.Errorf("store: unknown rule policy scope %q", p.Scope)
	}
	switch p.State {
	case RuleStateDefault, RuleStateEnabled, RuleStateDisabled:
	default:
		return fmt.Errorf("store: unknown rule state %q", p.State)
	}
	if p.Key = strings.TrimSpace(p.Key); p.Key == "" {
		return fmt.Errorf("store: a rule policy needs a target")
	}
	if p.Severity < 0 || p.Severity > 4 {
		return fmt.Errorf("store: severity override must be 1-4, or 0 for none")
	}

	// A policy that says nothing is not a policy. Removing the row rather than
	// storing an empty one keeps "how many rules have I overridden" honest.
	if !p.Opinionated() && p.Note == "" {
		return s.ClearRulePolicy(p.Scope, p.Key)
	}

	ts := now()
	_, err := s.db.Exec(`
		INSERT INTO rule_policy (scope, key, state, autoblock, autoblock_ttl, severity,
			note, actor, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(scope, key) DO UPDATE SET
			state = excluded.state, autoblock = excluded.autoblock,
			autoblock_ttl = excluded.autoblock_ttl, severity = excluded.severity,
			note = excluded.note, actor = excluded.actor, updated_at = excluded.updated_at`,
		p.Scope, p.Key, p.State, p.AutoBlock, p.AutoBlockTTL, p.Severity,
		p.Note, p.Actor, ts, ts)
	if err != nil {
		return fmt.Errorf("store: set rule policy: %w", err)
	}
	return nil
}

// ClearRulePolicy removes a decision, returning the rule to whatever the
// ruleset ships.
func (s *Store) ClearRulePolicy(scope, key string) error {
	_, err := s.db.Exec(`DELETE FROM rule_policy WHERE scope = ? AND key = ?`, scope, key)
	if err != nil {
		return fmt.Errorf("store: clear rule policy: %w", err)
	}
	return nil
}

// GetRulePolicy returns one decision. A missing row is not an error — it is the
// common case, and means "no opinion".
func (s *Store) GetRulePolicy(scope, key string) (RulePolicy, error) {
	p := RulePolicy{Scope: scope, Key: key}
	var created, updated string
	err := s.db.QueryRow(`
		SELECT state, autoblock, autoblock_ttl, severity, note, actor, created_at, updated_at
		FROM rule_policy WHERE scope = ? AND key = ?`, scope, key).
		Scan(&p.State, &p.AutoBlock, &p.AutoBlockTTL, &p.Severity, &p.Note, &p.Actor, &created, &updated)
	if err == sql.ErrNoRows {
		return RulePolicy{}, nil
	}
	if err != nil {
		return RulePolicy{}, fmt.Errorf("store: get rule policy: %w", err)
	}
	p.CreatedAt, p.UpdatedAt = ParseTime(created), ParseTime(updated)
	return p, nil
}

// RulePolicies returns every decision, most recently changed first.
func (s *Store) RulePolicies() ([]RulePolicy, error) {
	rows, err := s.db.Query(`
		SELECT scope, key, state, autoblock, autoblock_ttl, severity, note, actor,
			created_at, updated_at
		FROM rule_policy ORDER BY updated_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("store: list rule policies: %w", err)
	}
	defer rows.Close()
	var out []RulePolicy
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// RulePoliciesByScope returns the decisions in one scope, keyed for lookup.
func (s *Store) RulePoliciesByScope(scope string) (map[string]RulePolicy, error) {
	rows, err := s.db.Query(`
		SELECT scope, key, state, autoblock, autoblock_ttl, severity, note, actor,
			created_at, updated_at
		FROM rule_policy WHERE scope = ?`, scope)
	if err != nil {
		return nil, fmt.Errorf("store: rule policies by scope: %w", err)
	}
	defer rows.Close()
	out := map[string]RulePolicy{}
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		out[p.Key] = p
	}
	return out, rows.Err()
}

func scanPolicy(rows *sql.Rows) (RulePolicy, error) {
	var p RulePolicy
	var created, updated string
	if err := rows.Scan(&p.Scope, &p.Key, &p.State, &p.AutoBlock, &p.AutoBlockTTL,
		&p.Severity, &p.Note, &p.Actor, &created, &updated); err != nil {
		return RulePolicy{}, fmt.Errorf("store: scan rule policy: %w", err)
	}
	p.CreatedAt, p.UpdatedAt = ParseTime(created), ParseTime(updated)
	return p, nil
}

// ── what ingest needs ────────────────────────────────────────────────────

// RuleReactions is the per-signature behaviour ingest applies as alerts arrive:
// which rules block their source on sight, and which have a severity override.
//
// Category-scoped decisions are expanded to their member sids here rather than
// checked per alert, so the hot path is one map lookup. The expansion needs the
// catalogue, so a category-scoped auto-block on a meerkat that has never
// indexed a ruleset covers nothing — which is the safe direction to fail.
type RuleReactions struct {
	AutoBlock map[int]RulePolicy
	Severity  map[int]int
}

// Reactions loads the per-sid behaviour, expanding category policies.
func (s *Store) Reactions() (RuleReactions, error) {
	out := RuleReactions{AutoBlock: map[int]RulePolicy{}, Severity: map[int]int{}}

	cats, err := s.RulePoliciesByScope(RuleScopeCategory)
	if err != nil {
		return out, err
	}
	if len(cats) > 0 {
		names := make([]any, 0, len(cats))
		for name := range cats {
			names = append(names, name)
		}
		q := `SELECT sid, category FROM rules WHERE category IN (?` +
			strings.Repeat(",?", len(names)-1) + `)`
		rows, err := s.db.Query(q, names...)
		if err != nil {
			return out, fmt.Errorf("store: expand category policies: %w", err)
		}
		for rows.Next() {
			var sid int
			var cat string
			if err := rows.Scan(&sid, &cat); err != nil {
				rows.Close()
				return out, err
			}
			p := cats[cat]
			if p.AutoBlock {
				out.AutoBlock[sid] = p
			}
			if p.Severity > 0 {
				out.Severity[sid] = p.Severity
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return out, err
		}
	}

	// Per-sid decisions are applied second so they win over their category —
	// the same precedence suricata-update gives enable.conf over disable.conf,
	// and the one an operator expects from "mute the lot except this".
	sids, err := s.RulePoliciesByScope(RuleScopeSID)
	if err != nil {
		return out, err
	}
	for key, p := range sids {
		sid, err := strconv.Atoi(key)
		if err != nil {
			continue
		}
		if p.AutoBlock {
			out.AutoBlock[sid] = p
		} else {
			delete(out.AutoBlock, sid)
		}
		if p.Severity > 0 {
			out.Severity[sid] = p.Severity
		}
	}
	return out, nil
}

// ── run history ──────────────────────────────────────────────────────────

// Rule run kinds.
const (
	RuleRunApply = "apply"
	RuleRunIndex = "index"
	RuleRunAdopt = "adopt"
)

// RuleRun is one rule-management operation and its outcome.
type RuleRun struct {
	ID           int64
	StartedAt    time.Time
	FinishedAt   time.Time
	Kind         string
	Actor        string
	Reason       string
	OK           bool
	Step         string
	Error        string
	RulesTotal   int
	RulesEnabled int
	Added        int
	Removed      int
	Reloaded     bool
	Detail       string
	Log          string
}

// Duration is how long the run took.
func (r RuleRun) Duration() time.Duration {
	if r.StartedAt.IsZero() || r.FinishedAt.IsZero() {
		return 0
	}
	return r.FinishedAt.Sub(r.StartedAt).Round(time.Second)
}

// RecordRuleRun stores an operation. Failures are recorded exactly as
// faithfully as successes: a rule change that did not reach the sensor is the
// thing somebody will need to find later.
func (s *Store) RecordRuleRun(r RuleRun) (int64, error) {
	res, err := s.db.Exec(`
		INSERT INTO rule_runs (started_at, finished_at, kind, actor, reason, ok, step, error,
			rules_total, rules_enabled, added, removed, reloaded, detail, log, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		FormatTime(r.StartedAt), FormatTime(r.FinishedAt), r.Kind, r.Actor, r.Reason,
		r.OK, r.Step, r.Error, r.RulesTotal, r.RulesEnabled, r.Added, r.Removed,
		r.Reloaded, r.Detail, r.Log, now())
	if err != nil {
		return 0, fmt.Errorf("store: record rule run: %w", err)
	}
	return res.LastInsertId()
}

// RuleRuns returns the most recent operations.
func (s *Store) RuleRuns(limit int) ([]RuleRun, error) {
	rows, err := s.db.Query(`
		SELECT id, started_at, finished_at, kind, actor, reason, ok, step, error,
			rules_total, rules_enabled, added, removed, reloaded, detail, log
		FROM rule_runs ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list rule runs: %w", err)
	}
	defer rows.Close()
	var out []RuleRun
	for rows.Next() {
		var r RuleRun
		var started, finished string
		if err := rows.Scan(&r.ID, &started, &finished, &r.Kind, &r.Actor, &r.Reason,
			&r.OK, &r.Step, &r.Error, &r.RulesTotal, &r.RulesEnabled, &r.Added,
			&r.Removed, &r.Reloaded, &r.Detail, &r.Log); err != nil {
			return nil, fmt.Errorf("store: scan rule run: %w", err)
		}
		r.StartedAt, r.FinishedAt = ParseTime(started), ParseTime(finished)
		out = append(out, r)
	}
	return out, rows.Err()
}

// LastRuleRun returns the most recent run of a kind, if there is one. Empty
// kind means any.
func (s *Store) LastRuleRun(kind string) (RuleRun, bool, error) {
	q := `SELECT id FROM rule_runs`
	var args []any
	if kind != "" {
		q += ` WHERE kind = ?`
		args = append(args, kind)
	}
	q += ` ORDER BY id DESC LIMIT 1`
	var id int64
	if err := s.db.QueryRow(q, args...).Scan(&id); err == sql.ErrNoRows {
		return RuleRun{}, false, nil
	} else if err != nil {
		return RuleRun{}, false, fmt.Errorf("store: last rule run: %w", err)
	}
	runs, err := s.RuleRuns(50)
	if err != nil {
		return RuleRun{}, false, err
	}
	for _, r := range runs {
		if r.ID == id {
			return r, true, nil
		}
	}
	return RuleRun{}, false, nil
}

// PruneRuleRuns keeps the history bounded. Rule changes are infrequent, so this
// is about the log not growing without limit over years rather than about size.
func (s *Store) PruneRuleRuns(keep int) error {
	_, err := s.db.Exec(`
		DELETE FROM rule_runs WHERE id NOT IN (
			SELECT id FROM rule_runs ORDER BY id DESC LIMIT ?)`, keep)
	if err != nil {
		return fmt.Errorf("store: prune rule runs: %w", err)
	}
	return nil
}
