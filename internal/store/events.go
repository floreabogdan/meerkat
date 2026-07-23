package store

import (
	"database/sql"
	"fmt"
	"time"
)

// Alert is one enriched Suricata alert on its way into the database. The
// enrichment fields are flattened rather than carrying a geo.Geo so that store
// stays free of the geo package.
type Alert struct {
	Ts       time.Time
	SrcIP    string
	SrcPort  int
	DestIP   string
	DestPort int
	Proto    string
	AppProto string
	Iface    string
	SID      int
	GID      int
	Rev      int
	Sig      string
	Category string
	// RuleCategory is the signature's message prefix ("ET CINS"). Category
	// above is Suricata's classtype description ("Misc Attack") — a coarser
	// axis that puts the reputation feeds and a real intrusion in one bucket,
	// which is why rule management uses this one.
	RuleCategory string
	Severity     int
	Action       string
	FlowID       int64
	Extra        string // small JSON: http/tls/dns/ssh context, or ""

	// Enrichment of the source address.
	ASN         uint32
	ASOrg       string
	Country     string
	CountryName string
	Continent   string
	City        string
	Lat         float64
	Lon         float64
	IsLocal     bool
}

// Event is one stored alert, as the source-detail and live views read it back.
type Event struct {
	ID        int64
	Ts        time.Time
	SrcIP     string
	SrcPort   int
	DestIP    string
	DestPort  int
	Proto     string
	AppProto  string
	Iface     string
	SID       int
	GID       int
	Rev       int
	Signature string
	Category  string
	Severity  int
	Action    string
	FlowID    int64
	Extra     string
}

// RecordAlerts writes a batch of alerts and brings every rollup up to date, in
// one transaction. Ingest batches deliberately: a flood is thousands of rows,
// and one transaction per alert would fsync per alert.
//
// Per alert this is four upserts. The two that matter are source_signatures and
// source_ports: each RETURNS its own hit count, and a returned 1 means "this
// pair is new", which is exactly when the denormalised distinct counters on
// sources (and the distinct-source counter on signatures) move. That keeps those
// counters exact without a COUNT(DISTINCT) anywhere.
func (s *Store) RecordAlerts(batch []Alert) error {
	if len(batch) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("store: record alerts: %w", err)
	}
	defer tx.Rollback()

	insEvent, err := tx.Prepare(`
		INSERT INTO events (ts, src_ip, src_port, dest_ip, dest_port, proto, app_proto, iface,
			sid, gid, rev, signature, category, severity, action, flow_id, extra)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("store: prepare event insert: %w", err)
	}
	defer insEvent.Close()

	// worst_severity is MIN over the severities actually seen, with 0 ("nothing
	// recorded") never winning — otherwise the first alert lacking a severity
	// would permanently reset a source that had already shown a severity 1.
	upSource, err := tx.Prepare(`
		INSERT INTO sources (ip, first_seen, last_seen, event_count, worst_severity,
			asn, as_org, country, country_name, continent, city, lat, lon, is_local, created_at, updated_at)
		VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET
			first_seen  = MIN(first_seen, excluded.first_seen),
			last_seen   = MAX(last_seen, excluded.last_seen),
			event_count = event_count + 1,
			worst_severity = CASE
				WHEN worst_severity = 0 THEN excluded.worst_severity
				WHEN excluded.worst_severity = 0 THEN worst_severity
				ELSE MIN(worst_severity, excluded.worst_severity) END,
			asn = excluded.asn, as_org = excluded.as_org,
			country = excluded.country, country_name = excluded.country_name,
			continent = excluded.continent, city = excluded.city,
			lat = excluded.lat, lon = excluded.lon,
			is_local = excluded.is_local,
			updated_at = excluded.updated_at`)
	if err != nil {
		return fmt.Errorf("store: prepare source upsert: %w", err)
	}
	defer upSource.Close()

	upSourceSig, err := tx.Prepare(`
		INSERT INTO source_signatures (ip, sid, hits, first_seen, last_seen)
		VALUES (?, ?, 1, ?, ?)
		ON CONFLICT(ip, sid) DO UPDATE SET
			hits = hits + 1,
			first_seen = MIN(first_seen, excluded.first_seen),
			last_seen  = MAX(last_seen, excluded.last_seen)
		RETURNING hits`)
	if err != nil {
		return fmt.Errorf("store: prepare source_signature upsert: %w", err)
	}
	defer upSourceSig.Close()

	upSourcePort, err := tx.Prepare(`
		INSERT INTO source_ports (ip, proto, port, hits, last_seen)
		VALUES (?, ?, ?, 1, ?)
		ON CONFLICT(ip, proto, port) DO UPDATE SET
			hits = hits + 1,
			last_seen = MAX(last_seen, excluded.last_seen)
		RETURNING hits`)
	if err != nil {
		return fmt.Errorf("store: prepare source_port upsert: %w", err)
	}
	defer upSourcePort.Close()

	upSig, err := tx.Prepare(`
		INSERT INTO signatures (sid, gid, rev, signature, category, rule_category, severity, hits,
			source_count, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, 1, 0, ?, ?)
		ON CONFLICT(sid) DO UPDATE SET
			gid = excluded.gid, rev = excluded.rev,
			signature = excluded.signature, category = excluded.category,
			rule_category = excluded.rule_category,
			severity = CASE
				WHEN severity = 0 THEN excluded.severity
				WHEN excluded.severity = 0 THEN severity
				ELSE MIN(severity, excluded.severity) END,
			hits = hits + 1,
			first_seen = MIN(first_seen, excluded.first_seen),
			last_seen  = MAX(last_seen, excluded.last_seen)`)
	if err != nil {
		return fmt.Errorf("store: prepare signature upsert: %w", err)
	}
	defer upSig.Close()

	bumpSourceSigCount, err := tx.Prepare(`UPDATE sources SET sig_count = sig_count + 1 WHERE ip = ?`)
	if err != nil {
		return fmt.Errorf("store: prepare sig_count bump: %w", err)
	}
	defer bumpSourceSigCount.Close()

	bumpSourcePortCount, err := tx.Prepare(`UPDATE sources SET port_count = port_count + 1 WHERE ip = ?`)
	if err != nil {
		return fmt.Errorf("store: prepare port_count bump: %w", err)
	}
	defer bumpSourcePortCount.Close()

	bumpSigSources, err := tx.Prepare(`UPDATE signatures SET source_count = source_count + 1 WHERE sid = ?`)
	if err != nil {
		return fmt.Errorf("store: prepare source_count bump: %w", err)
	}
	defer bumpSigSources.Close()

	for _, a := range batch {
		ts := FormatTime(a.Ts)

		if _, err := insEvent.Exec(ts, a.SrcIP, a.SrcPort, a.DestIP, a.DestPort, a.Proto,
			a.AppProto, a.Iface, a.SID, a.GID, a.Rev, a.Sig, a.Category, a.Severity,
			a.Action, a.FlowID, a.Extra); err != nil {
			return fmt.Errorf("store: insert event: %w", err)
		}

		if _, err := upSource.Exec(a.SrcIP, ts, ts, a.Severity, a.ASN, a.ASOrg, a.Country,
			a.CountryName, a.Continent, a.City, a.Lat, a.Lon, a.IsLocal, ts, ts); err != nil {
			return fmt.Errorf("store: upsert source: %w", err)
		}

		if a.SID != 0 {
			if _, err := upSig.Exec(a.SID, a.GID, a.Rev, a.Sig, a.Category, a.RuleCategory,
				a.Severity, ts, ts); err != nil {
				return fmt.Errorf("store: upsert signature: %w", err)
			}
			var hits int
			if err := upSourceSig.QueryRow(a.SrcIP, a.SID, ts, ts).Scan(&hits); err != nil {
				return fmt.Errorf("store: upsert source signature: %w", err)
			}
			if hits == 1 { // first time this source tripped this signature
				if _, err := bumpSourceSigCount.Exec(a.SrcIP); err != nil {
					return fmt.Errorf("store: bump sig_count: %w", err)
				}
				if _, err := bumpSigSources.Exec(a.SID); err != nil {
					return fmt.Errorf("store: bump source_count: %w", err)
				}
			}
		}

		// Port 0 means the protocol has none (ICMP, and the GPL ICMP rules are
		// 10.6% of the flood) — not a port this source touched.
		if a.DestPort != 0 {
			var hits int
			if err := upSourcePort.QueryRow(a.SrcIP, a.Proto, a.DestPort, ts).Scan(&hits); err != nil {
				return fmt.Errorf("store: upsert source port: %w", err)
			}
			if hits == 1 {
				if _, err := bumpSourcePortCount.Exec(a.SrcIP); err != nil {
					return fmt.Errorf("store: bump port_count: %w", err)
				}
			}
		}
	}

	return tx.Commit()
}

const eventCols = `id, ts, src_ip, src_port, dest_ip, dest_port, proto, app_proto, iface,
	sid, gid, rev, signature, category, severity, action, flow_id, extra`

func scanEvents(rows *sql.Rows) ([]Event, error) {
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.SrcIP, &e.SrcPort, &e.DestIP, &e.DestPort,
			&e.Proto, &e.AppProto, &e.Iface, &e.SID, &e.GID, &e.Rev, &e.Signature,
			&e.Category, &e.Severity, &e.Action, &e.FlowID, &e.Extra); err != nil {
			return nil, fmt.Errorf("store: scan event: %w", err)
		}
		e.Ts = ParseTime(ts)
		out = append(out, e)
	}
	return out, rows.Err()
}

// EventsForSource returns a source's most recent events, newest first.
func (s *Store) EventsForSource(ip string, limit int) ([]Event, error) {
	rows, err := s.db.Query(`SELECT `+eventCols+` FROM events WHERE src_ip = ? ORDER BY ts DESC, id DESC LIMIT ?`, ip, limit)
	if err != nil {
		return nil, fmt.Errorf("store: events for source: %w", err)
	}
	return scanEvents(rows)
}

// RecentEvents returns the newest events, for the live view's first paint.
func (s *Store) RecentEvents(limit int) ([]Event, error) {
	rows, err := s.db.Query(`SELECT `+eventCols+` FROM events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: recent events: %w", err)
	}
	return scanEvents(rows)
}

// EventsAfter returns events with an id greater than afterID, oldest first —
// what the live view polls for. Pass 0 for "the latest page", which the caller
// then reverses.
func (s *Store) EventsAfter(afterID int64, limit int) ([]Event, error) {
	rows, err := s.db.Query(`SELECT `+eventCols+` FROM events WHERE id > ? ORDER BY id ASC LIMIT ?`, afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("store: events after: %w", err)
	}
	return scanEvents(rows)
}

// MaxEventID is the newest stored event id, so the live view can start polling
// from "now" without first fetching a page.
func (s *Store) MaxEventID() (int64, error) {
	var id sql.NullInt64
	if err := s.db.QueryRow(`SELECT MAX(id) FROM events`).Scan(&id); err != nil {
		return 0, fmt.Errorf("store: max event id: %w", err)
	}
	return id.Int64, nil
}

// Counts is the headline summary the sources page shows above the table.
type Counts struct {
	Events      int64
	Sources     int64
	Signatures  int64
	NewSources  int64
	Blocked     int64
	OldestEvent time.Time
	NewestEvent time.Time
}

// Summary reads the headline counts in one pass.
func (s *Store) Summary() (Counts, error) {
	var c Counts
	var oldest, newest sql.NullString
	err := s.db.QueryRow(`
		SELECT (SELECT COUNT(*) FROM events),
		       (SELECT COUNT(*) FROM sources),
		       (SELECT COUNT(*) FROM signatures),
		       (SELECT COUNT(*) FROM sources WHERE state = 'new'),
		       (SELECT COUNT(*) FROM sources WHERE state = 'blocked'),
		       (SELECT MIN(ts) FROM events),
		       (SELECT MAX(ts) FROM events)`).
		Scan(&c.Events, &c.Sources, &c.Signatures, &c.NewSources, &c.Blocked, &oldest, &newest)
	if err != nil {
		return c, fmt.Errorf("store: summary: %w", err)
	}
	c.OldestEvent = ParseTime(oldest.String)
	c.NewestEvent = ParseTime(newest.String)
	return c, nil
}

// PruneResult reports what a retention pass removed.
type PruneResult struct {
	Events  int64
	Sources int64
	OverCap int64 // events dropped by the max_events backstop rather than by age
}

// Prune enforces retention. Events older than the window go first; then, if the
// table is still over maxEvents, the oldest rows above the cap go too — a flood
// can otherwise fill the disk well inside a 7-day window.
//
// Sources are pruned only when they have aged out AND were never triaged.
// A source someone acknowledged, blocked or allowlisted is a decision, and
// decisions outlive the events that prompted them.
func (s *Store) Prune(olderThan time.Time, maxEvents int64) (PruneResult, error) {
	var res PruneResult
	cutoff := FormatTime(olderThan)

	r, err := s.db.Exec(`DELETE FROM events WHERE ts < ?`, cutoff)
	if err != nil {
		return res, fmt.Errorf("store: prune events: %w", err)
	}
	res.Events, _ = r.RowsAffected()

	if maxEvents > 0 {
		// id is monotonic, so "everything below (newest id - cap)" is exactly the
		// oldest rows over the cap, and the delete rides the primary key.
		r, err := s.db.Exec(`
			DELETE FROM events WHERE id <= (SELECT MAX(id) - ? FROM events)
			  AND (SELECT COUNT(*) FROM events) > ?`, maxEvents, maxEvents)
		if err != nil {
			return res, fmt.Errorf("store: prune events over cap: %w", err)
		}
		res.OverCap, _ = r.RowsAffected()
	}

	r, err = s.db.Exec(`DELETE FROM sources WHERE last_seen < ? AND state = 'new'`, cutoff)
	if err != nil {
		return res, fmt.Errorf("store: prune sources: %w", err)
	}
	res.Sources, _ = r.RowsAffected()

	// The rollup tables have no foreign key to sources (they are written on the
	// hot path, where an FK check per row is pure cost), so orphans are cleaned
	// up here instead.
	for _, q := range []string{
		`DELETE FROM source_signatures WHERE ip NOT IN (SELECT ip FROM sources)`,
		`DELETE FROM source_ports WHERE ip NOT IN (SELECT ip FROM sources)`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			return res, fmt.Errorf("store: prune rollups: %w", err)
		}
	}
	return res, nil
}

// HourBucket is one hour of alert volume, for the dashboard's activity chart.
type HourBucket struct {
	Start time.Time
	Count int64
}

// HourlyActivity returns alert counts per hour over the last n hours, oldest
// first, with empty hours included as zeroes so the chart has no gaps.
//
// The bucketing is done in SQL on the stored timestamp's prefix rather than by
// reading every row: at 300k alerts a day, pulling them into Go to count them
// would be the most expensive thing the dashboard does.
func (s *Store) HourlyActivity(hours int) ([]HourBucket, error) {
	if hours <= 0 {
		hours = 24
	}
	now := time.Now().UTC().Truncate(time.Hour)
	from := now.Add(-time.Duration(hours-1) * time.Hour)

	rows, err := s.db.Query(`
		SELECT substr(ts, 1, 13) AS hour, COUNT(*)
		FROM events WHERE ts >= ?
		GROUP BY hour`, FormatTime(from))
	if err != nil {
		return nil, fmt.Errorf("store: hourly activity: %w", err)
	}
	defer rows.Close()

	counts := make(map[string]int64, hours)
	for rows.Next() {
		var hour string
		var n int64
		if err := rows.Scan(&hour, &n); err != nil {
			return nil, fmt.Errorf("store: scan hourly activity: %w", err)
		}
		counts[hour] = n
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]HourBucket, 0, hours)
	for i := range hours {
		t := from.Add(time.Duration(i) * time.Hour)
		// The stored format is fixed-width, so the first 13 characters are
		// exactly "YYYY-MM-DDTHH" — the hour key.
		out = append(out, HourBucket{Start: t, Count: counts[FormatTime(t)[:13]]})
	}
	return out, nil
}

// TopSources returns the busiest sources, for the dashboard's leaderboard.
func (s *Store) TopSources(limit int) ([]Source, error) {
	rows, err := s.db.Query(`SELECT `+sourceCols+` FROM sources ORDER BY event_count DESC, last_seen DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: top sources: %w", err)
	}
	return scanSources(rows)
}
