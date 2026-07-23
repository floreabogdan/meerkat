package store

import (
	"fmt"
	"time"
)

// Per-signature dispositions. Phase 3 acts on these; Phase 1 records them so
// the shape of "mute ET CINS in one click" is already in the data model.
const (
	DispositionNotify = "notify"
	DispositionDigest = "digest"
	DispositionMute   = "mute"
)

// Signature is one Suricata rule as meerkat has seen it fire.
type Signature struct {
	SID         int
	GID         int
	Rev         int
	Signature   string
	Category    string
	Severity    int
	Hits        int64
	SourceCount int64
	FirstSeen   time.Time
	LastSeen    time.Time
	Disposition string
}

const signatureCols = `sid, gid, rev, signature, category, severity, hits, source_count,
	first_seen, last_seen, disposition`

// TopSignatures returns the loudest signatures first — which is how the
// reputation-list noise announces itself: on the reference sensor, ET CINS alone was 68.8% of
// everything.
func (s *Store) TopSignatures(limit int) ([]Signature, error) {
	rows, err := s.db.Query(`SELECT `+signatureCols+` FROM signatures ORDER BY hits DESC, sid LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: top signatures: %w", err)
	}
	defer rows.Close()
	var out []Signature
	for rows.Next() {
		var g Signature
		var first, last string
		if err := rows.Scan(&g.SID, &g.GID, &g.Rev, &g.Signature, &g.Category, &g.Severity,
			&g.Hits, &g.SourceCount, &first, &last, &g.Disposition); err != nil {
			return nil, fmt.Errorf("store: scan signature: %w", err)
		}
		g.FirstSeen, g.LastSeen = ParseTime(first), ParseTime(last)
		out = append(out, g)
	}
	return out, rows.Err()
}

// CategoryCount is one Suricata category with its share of the alert volume —
// the breakdown that made the case for this project.
type CategoryCount struct {
	Category string
	Hits     int64
}

// CategoryBreakdown returns alert volume by category, loudest first.
func (s *Store) CategoryBreakdown(limit int) ([]CategoryCount, error) {
	rows, err := s.db.Query(`
		SELECT COALESCE(NULLIF(category, ''), 'uncategorised'), SUM(hits)
		FROM signatures GROUP BY category ORDER BY SUM(hits) DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: category breakdown: %w", err)
	}
	defer rows.Close()
	var out []CategoryCount
	for rows.Next() {
		var c CategoryCount
		if err := rows.Scan(&c.Category, &c.Hits); err != nil {
			return nil, fmt.Errorf("store: scan category: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SetDisposition changes how a signature is treated.
func (s *Store) SetDisposition(sid int, disposition string) error {
	switch disposition {
	case DispositionNotify, DispositionDigest, DispositionMute:
	default:
		return fmt.Errorf("store: unknown disposition %q", disposition)
	}
	res, err := s.db.Exec(`UPDATE signatures SET disposition = ? WHERE sid = ?`, disposition, sid)
	if err != nil {
		return fmt.Errorf("store: set disposition: %w", err)
	}
	return notFoundIfZero(res)
}
