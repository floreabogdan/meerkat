package store

import (
	"database/sql"
	"fmt"
)

// schemaVersion is the migration level this build expects. The CREATE TABLE
// statements in schema.go are all IF NOT EXISTS and run unconditionally, so
// migrations here only handle what that cannot express: new columns on tables
// that already exist, and one-time data fixes. Bump this and add a case when the
// shape of an existing database has to change.
//
// meerkat's database is a single file the operator can snapshot and restore, so
// migrations must be forward-only and safe to re-run.
const schemaVersion = 5

func migrate(db *sql.DB) error {
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("read user_version: %w", err)
	}
	if version >= schemaVersion {
		return nil
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, a := range columnAdds {
		if err := addColumnIfMissing(tx, a.table, a.column, a.ddl); err != nil {
			return err
		}
	}
	// Indexes over migrated columns belong here, not in schema.go: that file is
	// applied before this one runs, and on an existing database the column it
	// names does not exist yet.
	for _, stmt := range migratedIndexes {
		if _, err := tx.Exec(stmt); err != nil {
			return fmt.Errorf("create index: %w", err)
		}
	}

	// version < 3: the look was aligned with birdy, whose accent is green. Move
	// databases still sitting on the old 'ocean' default across — that value was
	// never a choice anyone made, it was just what the column defaulted to. An
	// accent the operator actually picked is left alone.
	if version < 3 {
		if _, err := tx.Exec(`UPDATE settings SET theme_accent = 'green' WHERE theme_accent = 'ocean' OR theme_accent = ''`); err != nil {
			return fmt.Errorf("align default accent: %w", err)
		}
	}

	if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, schemaVersion)); err != nil {
		return fmt.Errorf("set user_version: %w", err)
	}
	return tx.Commit()
}

// columnAdds brings a database created before a column existed up to date. A
// fresh database already has each via schema.go, so addColumnIfMissing is a
// no-op there.
//
// It is a package-level var so the upgrade test can walk it: for every entry,
// drop the column from a fresh database, wind user_version back, and reopen.
// That is the only way to exercise the path a real upgrade takes, and it is the
// path a test that always starts from the current schema never touches.
var columnAdds = []struct{ table, column, ddl string }{
	// version < 2: the threat-map shipper, and the source coordinates it
	// needs to plot a point.
	{"sources", "lat", `REAL NOT NULL DEFAULT 0`},
	{"sources", "lon", `REAL NOT NULL DEFAULT 0`},
	{"settings", "threats_enabled", `INTEGER NOT NULL DEFAULT 0`},
	{"settings", "threats_url", `TEXT NOT NULL DEFAULT ''`},
	{"settings", "threats_token", `TEXT NOT NULL DEFAULT ''`},
	{"settings", "site_name", `TEXT NOT NULL DEFAULT ''`},
	{"settings", "site_country", `TEXT NOT NULL DEFAULT ''`},
	{"settings", "site_lat", `REAL NOT NULL DEFAULT 0`},
	{"settings", "site_lng", `REAL NOT NULL DEFAULT 0`},
	{"settings", "threats_cursor", `INTEGER NOT NULL DEFAULT 0`},
	{"settings", "home_nets", `TEXT NOT NULL DEFAULT ''`},
	// version < 4: timed blocks.
	{"sources", "blocked_until", `TEXT NOT NULL DEFAULT ''`},
	// version < 5: managing Suricata's ruleset rather than only reading its
	// output. rule_category is the message-prefix axis ("ET CINS"), which
	// the classtype column was never carrying.
	{"signatures", "rule_category", `TEXT NOT NULL DEFAULT ''`},
	{"settings", "suricata_rules_path", `TEXT NOT NULL DEFAULT '/var/lib/suricata/rules/suricata.rules'`},
	{"settings", "suricata_conf_dir", `TEXT NOT NULL DEFAULT '/etc/suricata'`},
	{"settings", "suricata_socket", `TEXT NOT NULL DEFAULT '/var/run/suricata-command.socket'`},
	{"settings", "suricata_data_dir", `TEXT NOT NULL DEFAULT '/var/lib/suricata'`},
	{"settings", "rules_auto_update", `INTEGER NOT NULL DEFAULT 0`},
	{"settings", "rules_update_hour", `INTEGER NOT NULL DEFAULT 4`},
	{"settings", "rules_last_update", `TEXT NOT NULL DEFAULT ''`},
	{"settings", "autoblock_enabled", `INTEGER NOT NULL DEFAULT 0`},
	{"settings", "autoblock_max_hour", `INTEGER NOT NULL DEFAULT 20`},
}

// migratedIndexes are indexes over columns that columnAdds introduces. They
// cannot live in schema.go: that runs first, and on an existing database
// CREATE TABLE IF NOT EXISTS does nothing, so the column is not there yet and
// the whole schema step fails.
var migratedIndexes = []string{
	`CREATE INDEX IF NOT EXISTS idx_signatures_rule_category ON signatures(rule_category)`,
}

// addColumnIfMissing is ALTER TABLE ADD COLUMN, tolerant of the column already
// existing — which it does on databases created by a build that already had it
// in the base schema.
func addColumnIfMissing(tx *sql.Tx, table, column, ddl string) error {
	rows, err := tx.Query(fmt.Sprintf(`PRAGMA table_info(%q)`, table))
	if err != nil {
		return fmt.Errorf("table_info %s: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return fmt.Errorf("table_info %s: %w", table, err)
		}
		if name == column {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if _, err := tx.Exec(fmt.Sprintf(`ALTER TABLE %q ADD COLUMN %q %s`, table, column, ddl)); err != nil {
		return fmt.Errorf("add %s.%s: %w", table, column, err)
	}
	return nil
}
