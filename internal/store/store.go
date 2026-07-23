// Package store wraps meerkat's SQLite database: the Suricata alerts it has
// ingested, the per-source rollups the console is built on, plus settings, local
// user accounts and login sessions. modernc.org/sqlite is pure Go, so the whole
// tool cross-compiles from any host to the router without cgo.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// ErrNotFound is returned by Get/Update/Delete when the row does not exist.
var ErrNotFound = errors.New("not found")

// maxOpenConns bounds the connection pool. SQLite is single-writer, so a large
// pool buys nothing on the write side; WAL still lets these connections read
// concurrently. meerkat writes in batches from one ingest goroutine and reads
// from the web handlers, so a small cap is right — it keeps a burst from opening
// an unbounded number of connections (and racing on the write lock past the
// busy_timeout) without pinning to 1, which would deadlock any code path holding
// a transaction while issuing another query on the same goroutine.
const maxOpenConns = 4

// TimeFormat is how every timestamp column is written: UTC, fixed width, six
// fractional digits (Suricata's own precision).
//
// The fixed width is load-bearing, not cosmetic. Alerts are ordered, filtered by
// window and rolled up with MIN()/MAX() directly on these TEXT columns, which
// only agrees with chronological order if every value is the same length.
// time.RFC3339Nano trims trailing zeros, so "…:05Z" and "…:05.5Z" would compare
// as ".5Z" < "Z" — an event half a second later sorting earlier.
const TimeFormat = "2006-01-02T15:04:05.000000Z"

// FormatTime renders a timestamp for storage.
func FormatTime(t time.Time) string { return t.UTC().Format(TimeFormat) }

// ParseTime reads a stored timestamp back. It also accepts RFC3339Nano so rows
// written by an older build (or by hand) still load.
func ParseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(TimeFormat, s); err == nil {
		return t
	}
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}

// Store is meerkat's SQLite-backed state and the only thing that touches the
// database.
type Store struct {
	db *sql.DB
}

// Open opens (creating if necessary) the SQLite database at path and applies
// the schema.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)")
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	db.SetMaxOpenConns(maxOpenConns)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: apply schema: %w", err)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: migrate: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

// CheckWritable fails when the database can be read but not written — the state
// a root-created file leaves behind when the service then runs as another user.
// SQLite only complains at the first write, so nothing above notices: meerkat
// starts, serves a login page, and the login (which inserts a session row) is
// what finally breaks. Probing at startup turns that into one clear error.
func (s *Store) CheckWritable() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS write_probe (ok INTEGER)`); err != nil {
		return fmt.Errorf("store: database is not writable: %w", err)
	}
	if _, err := s.db.Exec(`DROP TABLE write_probe`); err != nil {
		return fmt.Errorf("store: database is not writable: %w", err)
	}
	return nil
}

func now() string {
	return FormatTime(time.Now())
}

// notFoundIfZero turns a zero-row UPDATE/DELETE into ErrNotFound, so a save
// against a missing row is a distinguishable failure rather than a silent no-op.
func notFoundIfZero(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
