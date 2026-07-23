package store

import (
	"fmt"
	"time"
)

// ship.go feeds the threat-map shipper. It reads forward from a persisted
// cursor rather than tapping the ingest pipeline in memory, which is what makes
// publishing survive a restart: nothing is re-published and nothing is skipped,
// because the cursor only advances after the collector has accepted a batch.

// Shippable is one alert joined to its source's enrichment, in the shape the
// public map's wire contract needs.
//
// Note what is NOT here: the destination address. The map reports destinations
// as a site name plus a port, never as a customer IP — this page is public, and
// publishing which hosts inside our ranges are live and being probed would be
// free reconnaissance. There is deliberately no way to select dest_ip through
// this type.
type Shippable struct {
	ID       int64
	Ts       time.Time
	Sig      string
	SID      int
	Severity int
	Proto    string
	DestPort int

	SrcIP   string
	SrcCC   string
	SrcCity string
	SrcLat  float64
	SrcLon  float64
	SrcASN  uint32
	SrcOrg  string

	// SourceState is the source's triage state, which decides whether this is
	// reported as "detected" or "blocked". Only a source actually banned in
	// nftables may claim the latter.
	SourceState string
	// IsLocal marks a private, loopback or CGNAT source. Never published.
	IsLocal bool
}

// Action is what honestly happened to this traffic. Suricata here runs
// alert-only, so an alert is "detected"; only an address actually banned in
// nftables is "blocked". This is the single place that mapping is made, so it
// cannot drift into flattering the dashboard.
func (s Shippable) Action() string {
	if s.SourceState == StateBlocked {
		return "blocked"
	}
	return "detected"
}

// ShippableAfter returns up to limit alerts with an id greater than afterID,
// oldest first, joined to their source enrichment.
//
// Local sources are excluded in SQL rather than in the caller: an internal
// address must not even be loaded into a payload struct that is about to be
// serialised. Our own public ranges are excluded by the caller, which is the
// only layer that knows them.
func (s *Store) ShippableAfter(afterID int64, limit int) ([]Shippable, error) {
	rows, err := s.db.Query(`
		SELECT e.id, e.ts, e.signature, e.sid, e.severity, e.proto, e.dest_port, e.src_ip,
		       COALESCE(s.country, ''), COALESCE(s.city, ''),
		       COALESCE(s.lat, 0), COALESCE(s.lon, 0),
		       COALESCE(s.asn, 0), COALESCE(s.as_org, ''),
		       COALESCE(s.state, ''), COALESCE(s.is_local, 0)
		FROM events e
		LEFT JOIN sources s ON s.ip = e.src_ip
		WHERE e.id > ? AND COALESCE(s.is_local, 0) = 0
		ORDER BY e.id ASC
		LIMIT ?`, afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("store: shippable after: %w", err)
	}
	defer rows.Close()

	var out []Shippable
	for rows.Next() {
		var sh Shippable
		var ts string
		if err := rows.Scan(&sh.ID, &ts, &sh.Sig, &sh.SID, &sh.Severity, &sh.Proto,
			&sh.DestPort, &sh.SrcIP, &sh.SrcCC, &sh.SrcCity, &sh.SrcLat, &sh.SrcLon,
			&sh.SrcASN, &sh.SrcOrg, &sh.SourceState, &sh.IsLocal); err != nil {
			return nil, fmt.Errorf("store: scan shippable: %w", err)
		}
		sh.Ts = ParseTime(ts)
		out = append(out, sh)
	}
	return out, rows.Err()
}

// HighestShippableID is the newest event id, so a shipper starting for the
// first time can begin at "now" instead of replaying the whole retention
// window onto a public map.
func (s *Store) HighestShippableID() (int64, error) {
	return s.MaxEventID()
}
