package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// Source states. Only Blocked asserts that the address is actually banned in
// nftables — nothing but a confirmed nftably block may set it, because
// "detected" and "blocked" have to mean what they say.
const (
	StateNew          = "new"
	StateAcknowledged = "acknowledged"
	StateBlocked      = "blocked"
	StateAllowlisted  = "allowlisted"
)

// ValidState reports whether s is one of the four triage states.
func ValidState(s string) bool {
	switch s {
	case StateNew, StateAcknowledged, StateBlocked, StateAllowlisted:
		return true
	}
	return false
}

// Source is one address rolled up: everything the operator needs to decide what
// to do about it, without reading a single event row.
type Source struct {
	IP            string
	FirstSeen     time.Time
	LastSeen      time.Time
	EventCount    int64
	SigCount      int
	PortCount     int
	WorstSeverity int

	ASN         uint32
	ASOrg       string
	Country     string
	CountryName string
	Continent   string
	City        string
	Lat         float64
	Lon         float64
	IsLocal     bool

	State     string
	StateNote string
	StateAt   time.Time
	StateBy   string
	// BlockedUntil is when a timed block lapses; zero means indefinite.
	BlockedUntil time.Time
}

// SourceFilter is the sources page's query: every control on the filter bar.
// The zero value means "everything, newest activity first".
type SourceFilter struct {
	Query   string // free text over ip / AS org / country / city
	Country string
	ASN     uint32
	State   string
	Port    int
	SID     int
	// MaxSeverity keeps sources whose worst severity is at least this severe.
	// Suricata counts down (1 = most severe), so this is an upper bound on the
	// stored number: 1 = high only, 3 = everything.
	MaxSeverity int
	// Since keeps sources active in the window; zero means no time filter.
	Since time.Time
	// MinEvents hides one-off noise.
	MinEvents int64

	Sort   string // last_seen|first_seen|events|severity|sigs|ports|ip
	Desc   bool
	Limit  int
	Offset int
}

var sourceSortColumns = map[string]string{
	"last_seen":  "last_seen",
	"first_seen": "first_seen",
	"events":     "event_count",
	"severity":   "worst_severity",
	"sigs":       "sig_count",
	"ports":      "port_count",
	"ip":         "ip",
}

// SortColumn resolves the requested sort to a column, defaulting to last_seen.
// Exported so the web layer can reject an unknown value instead of silently
// sorting by something else.
func SortColumn(name string) (string, bool) {
	col, ok := sourceSortColumns[name]
	return col, ok
}

const sourceCols = `ip, first_seen, last_seen, event_count, sig_count, port_count, worst_severity,
	asn, as_org, country, country_name, continent, city, lat, lon, is_local,
	state, state_note, state_at, state_by, blocked_until`

// where builds the shared WHERE clause and its arguments.
func (f SourceFilter) where() (string, []any) {
	var conds []string
	var args []any

	if q := strings.TrimSpace(f.Query); q != "" {
		like := "%" + q + "%"
		conds = append(conds, `(ip LIKE ? OR as_org LIKE ? OR country_name LIKE ? OR city LIKE ?)`)
		args = append(args, like, like, like, like)
	}
	if f.Country != "" {
		conds = append(conds, `country = ?`)
		args = append(args, f.Country)
	}
	if f.ASN != 0 {
		conds = append(conds, `asn = ?`)
		args = append(args, f.ASN)
	}
	if f.State != "" {
		conds = append(conds, `state = ?`)
		args = append(args, f.State)
	}
	if f.MaxSeverity > 0 {
		// worst_severity 0 means nothing was recorded, which is not "severe".
		conds = append(conds, `worst_severity > 0 AND worst_severity <= ?`)
		args = append(args, f.MaxSeverity)
	}
	if !f.Since.IsZero() {
		conds = append(conds, `last_seen >= ?`)
		args = append(args, FormatTime(f.Since))
	}
	if f.MinEvents > 0 {
		conds = append(conds, `event_count >= ?`)
		args = append(args, f.MinEvents)
	}
	if f.SID != 0 {
		conds = append(conds, `EXISTS (SELECT 1 FROM source_signatures ss WHERE ss.ip = sources.ip AND ss.sid = ?)`)
		args = append(args, f.SID)
	}
	if f.Port != 0 {
		conds = append(conds, `EXISTS (SELECT 1 FROM source_ports sp WHERE sp.ip = sources.ip AND sp.port = ?)`)
		args = append(args, f.Port)
	}

	if len(conds) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

// ListSources runs the sources page's query and also reports how many rows
// matched before the limit, so the UI can say "showing 50 of 4,812".
func (s *Store) ListSources(f SourceFilter) ([]Source, int64, error) {
	where, args := f.where()

	var total int64
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sources`+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("store: count sources: %w", err)
	}

	col, ok := SortColumn(f.Sort)
	if !ok {
		col = "last_seen"
	}
	dir := "ASC"
	if f.Desc {
		dir = "DESC"
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}

	// col comes from the fixed map above, never from user input, so interpolating
	// it is safe; every value is still a bound parameter.
	q := fmt.Sprintf(`SELECT %s FROM sources%s ORDER BY %s %s, ip ASC LIMIT ? OFFSET ?`,
		sourceCols, where, col, dir)
	rows, err := s.db.Query(q, append(args, limit, f.Offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("store: list sources: %w", err)
	}
	out, err := scanSources(rows)
	return out, total, err
}

func scanSources(rows *sql.Rows) ([]Source, error) {
	defer rows.Close()
	var out []Source
	for rows.Next() {
		src, err := scanSource(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, src)
	}
	return out, rows.Err()
}

type scanner interface{ Scan(dest ...any) error }

func scanSource(sc scanner) (Source, error) {
	var s Source
	var first, last, stateAt, until string
	err := sc.Scan(&s.IP, &first, &last, &s.EventCount, &s.SigCount, &s.PortCount, &s.WorstSeverity,
		&s.ASN, &s.ASOrg, &s.Country, &s.CountryName, &s.Continent, &s.City, &s.Lat, &s.Lon, &s.IsLocal,
		&s.State, &s.StateNote, &stateAt, &s.StateBy, &until)
	if err != nil {
		return Source{}, err
	}
	s.FirstSeen, s.LastSeen, s.StateAt = ParseTime(first), ParseTime(last), ParseTime(stateAt)
	s.BlockedUntil = ParseTime(until)
	return s, nil
}

// GetSource returns one source, or ErrNotFound.
func (s *Store) GetSource(ip string) (Source, error) {
	row := s.db.QueryRow(`SELECT `+sourceCols+` FROM sources WHERE ip = ?`, ip)
	src, err := scanSource(row)
	if err == sql.ErrNoRows {
		return Source{}, ErrNotFound
	}
	if err != nil {
		return Source{}, fmt.Errorf("store: get source: %w", err)
	}
	return src, nil
}

// SetSourceState records a triage decision. The caller is responsible for having
// actually done the thing — SetSourceState(StateBlocked) after a failed nftably
// call would be a lie the actions log could not correct.
func (s *Store) SetSourceState(ip, state, note, by string) error {
	return s.SetSourceStateUntil(ip, state, note, by, time.Time{})
}

// SetSourceStateUntil is SetSourceState with an expiry, for a timed block. A
// zero until clears any previous expiry, so unblocking or re-blocking
// indefinitely does not leave a stale one behind.
func (s *Store) SetSourceStateUntil(ip, state, note, by string, until time.Time) error {
	if !ValidState(state) {
		return fmt.Errorf("store: unknown source state %q", state)
	}
	stamp := ""
	if !until.IsZero() {
		stamp = FormatTime(until)
	}
	res, err := s.db.Exec(`UPDATE sources SET state = ?, state_note = ?, state_at = ?, state_by = ?, blocked_until = ?, updated_at = ? WHERE ip = ?`,
		state, note, now(), by, stamp, now(), ip)
	if err != nil {
		return fmt.Errorf("store: set source state: %w", err)
	}
	return notFoundIfZero(res)
}

// BlockedSources lists every source meerkat currently claims is blocked. The
// reconciler compares this against nftably's real set.
func (s *Store) BlockedSources() ([]Source, error) {
	rows, err := s.db.Query(`SELECT ` + sourceCols + ` FROM sources WHERE state = 'blocked'`)
	if err != nil {
		return nil, fmt.Errorf("store: blocked sources: %w", err)
	}
	return scanSources(rows)
}

// ExpiredBlocks lists timed blocks whose expiry has passed.
func (s *Store) ExpiredBlocks(at time.Time) ([]Source, error) {
	rows, err := s.db.Query(`SELECT `+sourceCols+` FROM sources
		WHERE state = 'blocked' AND blocked_until != '' AND blocked_until <= ?`, FormatTime(at))
	if err != nil {
		return nil, fmt.Errorf("store: expired blocks: %w", err)
	}
	return scanSources(rows)
}

// SourceSignature is one signature a source tripped, joined to its text.
type SourceSignature struct {
	SID       int
	Signature string
	Category  string
	Severity  int
	Hits      int64
	FirstSeen time.Time
	LastSeen  time.Time
}

// SignaturesForSource lists what a source tripped, worst-and-loudest first.
func (s *Store) SignaturesForSource(ip string) ([]SourceSignature, error) {
	rows, err := s.db.Query(`
		SELECT ss.sid, COALESCE(g.signature, ''), COALESCE(g.category, ''), COALESCE(g.severity, 0),
		       ss.hits, ss.first_seen, ss.last_seen
		FROM source_signatures ss
		LEFT JOIN signatures g ON g.sid = ss.sid
		WHERE ss.ip = ?
		ORDER BY ss.hits DESC, ss.sid`, ip)
	if err != nil {
		return nil, fmt.Errorf("store: signatures for source: %w", err)
	}
	defer rows.Close()
	var out []SourceSignature
	for rows.Next() {
		var r SourceSignature
		var first, last string
		if err := rows.Scan(&r.SID, &r.Signature, &r.Category, &r.Severity, &r.Hits, &first, &last); err != nil {
			return nil, fmt.Errorf("store: scan source signature: %w", err)
		}
		r.FirstSeen, r.LastSeen = ParseTime(first), ParseTime(last)
		out = append(out, r)
	}
	return out, rows.Err()
}

// SourcePort is one destination port a source touched.
type SourcePort struct {
	Proto    string
	Port     int
	Hits     int64
	LastSeen time.Time
}

// PortsForSource lists the destination ports a source touched, busiest first.
func (s *Store) PortsForSource(ip string) ([]SourcePort, error) {
	rows, err := s.db.Query(`SELECT proto, port, hits, last_seen FROM source_ports WHERE ip = ? ORDER BY hits DESC, port`, ip)
	if err != nil {
		return nil, fmt.Errorf("store: ports for source: %w", err)
	}
	defer rows.Close()
	var out []SourcePort
	for rows.Next() {
		var p SourcePort
		var last string
		if err := rows.Scan(&p.Proto, &p.Port, &p.Hits, &last); err != nil {
			return nil, fmt.Errorf("store: scan source port: %w", err)
		}
		p.LastSeen = ParseTime(last)
		out = append(out, p)
	}
	return out, rows.Err()
}

// Facet is one value of a filterable dimension, with how many sources carry it —
// what fills the filter bar's dropdowns.
type Facet struct {
	Value string
	Label string
	Count int64
}

// CountryFacets lists the countries present, commonest first.
func (s *Store) CountryFacets(limit int) ([]Facet, error) {
	return s.facets(`
		SELECT country, COALESCE(MAX(country_name), ''), COUNT(*) FROM sources
		WHERE country != '' GROUP BY country ORDER BY COUNT(*) DESC LIMIT ?`, limit)
}

// ASNFacets lists the autonomous systems present, commonest first.
func (s *Store) ASNFacets(limit int) ([]Facet, error) {
	return s.facets(`
		SELECT CAST(asn AS TEXT), COALESCE(MAX(as_org), ''), COUNT(*) FROM sources
		WHERE asn != 0 GROUP BY asn ORDER BY COUNT(*) DESC LIMIT ?`, limit)
}

// PortFacets lists the destination ports being hit, busiest first.
func (s *Store) PortFacets(limit int) ([]Facet, error) {
	return s.facets(`
		SELECT CAST(port AS TEXT), '', COUNT(DISTINCT ip) FROM source_ports
		GROUP BY port ORDER BY COUNT(DISTINCT ip) DESC LIMIT ?`, limit)
}

func (s *Store) facets(query string, limit int) ([]Facet, error) {
	rows, err := s.db.Query(query, limit)
	if err != nil {
		return nil, fmt.Errorf("store: facets: %w", err)
	}
	defer rows.Close()
	var out []Facet
	for rows.Next() {
		var f Facet
		if err := rows.Scan(&f.Value, &f.Label, &f.Count); err != nil {
			return nil, fmt.Errorf("store: scan facet: %w", err)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}
