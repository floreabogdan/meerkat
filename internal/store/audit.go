package store

import (
	"database/sql"
	"fmt"
	"time"
)

// Audit kinds recorded on the operator timeline. These are things done to or by
// meerkat — not Suricata alerts, which are events.
const (
	AuditLogin        = "login"
	AuditLogout       = "logout"
	AuditSettings     = "settings_change"
	AuditIngestError  = "ingest_error"  // eve.json unreadable, parse failures
	AuditRetention    = "retention"     // a prune pass removed rows
	AuditSourceChange = "source_change" // a triage decision
)

// AuditEntry is one entry on the operator timeline.
type AuditEntry struct {
	ID      int64
	Ts      time.Time
	Kind    string
	Actor   string
	Message string
}

// InsertAudit appends one operator action, attributed to actor.
func (s *Store) InsertAudit(actor, kind, message string) error {
	ts := now()
	_, err := s.db.Exec(`INSERT INTO audit (ts, kind, actor, message, created_at) VALUES (?, ?, ?, ?, ?)`,
		ts, kind, actor, message, ts)
	if err != nil {
		return fmt.Errorf("store: insert audit: %w", err)
	}
	return nil
}

// InsertSystemAudit appends one system event with no actor.
func (s *Store) InsertSystemAudit(kind, message string) error {
	return s.InsertAudit("", kind, message)
}

// ListAudit returns up to limit most recent entries, optionally only those with
// id strictly less than beforeID (pagination — ids are monotonic, unlike
// timestamps, which can collide within an insert burst). Pass 0 for page one.
func (s *Store) ListAudit(limit int, beforeID int64) ([]AuditEntry, error) {
	var rows *sql.Rows
	var err error
	if beforeID == 0 {
		rows, err = s.db.Query(`SELECT id, ts, kind, actor, message FROM audit ORDER BY id DESC LIMIT ?`, limit)
	} else {
		rows, err = s.db.Query(`SELECT id, ts, kind, actor, message FROM audit WHERE id < ? ORDER BY id DESC LIMIT ?`,
			beforeID, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("store: list audit: %w", err)
	}
	defer rows.Close()

	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.Kind, &e.Actor, &e.Message); err != nil {
			return nil, fmt.Errorf("store: scan audit: %w", err)
		}
		e.Ts = ParseTime(ts)
		out = append(out, e)
	}
	return out, rows.Err()
}

// Action kinds — what an operator did to the network.
const (
	ActionBlock       = "block"
	ActionUnblock     = "unblock"
	ActionAllowlist   = "allowlist"
	ActionAcknowledge = "acknowledge"
	ActionMute        = "mute"
	ActionUnmute      = "unmute"
)

// Action is one record in the ledger of what was done to the network. It exists
// so that a source marked "blocked" can always be traced to the call that
// blocked it and what the far end said.
type Action struct {
	ID      int64
	Ts      time.Time
	Actor   string
	Action  string
	Target  string
	TTLSecs int
	Reason  string
	Result  string
	OK      bool
}

// RecordAction appends to the ledger.
func (s *Store) RecordAction(a Action) error {
	ts := now()
	_, err := s.db.Exec(`
		INSERT INTO actions (ts, actor, action, target, ttl_secs, reason, result, ok, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ts, a.Actor, a.Action, a.Target, a.TTLSecs, a.Reason, a.Result, a.OK, ts)
	if err != nil {
		return fmt.Errorf("store: record action: %w", err)
	}
	return nil
}

// ActionsForTarget returns the ledger entries for one address or signature,
// newest first.
func (s *Store) ActionsForTarget(target string, limit int) ([]Action, error) {
	rows, err := s.db.Query(`
		SELECT id, ts, actor, action, target, ttl_secs, reason, result, ok
		FROM actions WHERE target = ? ORDER BY id DESC LIMIT ?`, target, limit)
	if err != nil {
		return nil, fmt.Errorf("store: actions for target: %w", err)
	}
	defer rows.Close()
	var out []Action
	for rows.Next() {
		var a Action
		var ts string
		if err := rows.Scan(&a.ID, &ts, &a.Actor, &a.Action, &a.Target, &a.TTLSecs,
			&a.Reason, &a.Result, &a.OK); err != nil {
			return nil, fmt.Errorf("store: scan action: %w", err)
		}
		a.Ts = ParseTime(ts)
		out = append(out, a)
	}
	return out, rows.Err()
}
