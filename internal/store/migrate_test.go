package store

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// TestUpgradeFromAnOlderDatabase is the test that was missing, and its absence
// cost a production outage.
//
// Every other test in this package starts from a database the current build
// created, which means the schema is always already correct and migrate() never
// does anything. A real upgrade is the opposite case: the tables exist, some
// columns do not, and schema.go's CREATE TABLE IF NOT EXISTS is a no-op that
// silently leaves them missing. An index in schema.go naming one of those
// columns therefore fails on every existing database and on none of the tests —
// which is exactly what happened, and meerkat crash-looped on the router.
//
// This walks the actual upgrade: build a current database, strip every migrated
// column back out, wind user_version back to zero, and reopen.
func TestUpgradeFromAnOlderDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")

	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveIdentity("edge1", "0.0.0.0:8100"); err != nil {
		t.Fatal(err)
	}
	// Some real content, so the upgrade has rows to carry across rather than
	// running against empty tables.
	if err := st.RecordAlerts([]Alert{{
		Ts: time.Now().UTC(), SrcIP: "198.51.100.7", DestPort: 22, Proto: "TCP",
		SID: 2010371, Sig: "ET SCAN Amap", Category: "Attempted Recon", Severity: 2,
	}}); err != nil {
		t.Fatal(err)
	}
	st.Close()

	// Wind it back to something an older meerkat would have written.
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range migratedIndexes {
		name := indexNameOf(stmt)
		if name == "" {
			t.Fatalf("could not read an index name out of %q", stmt)
		}
		if _, err := db.Exec(`DROP INDEX IF EXISTS ` + name); err != nil {
			t.Fatalf("drop %s: %v", name, err)
		}
	}
	for _, a := range columnAdds {
		// SQLite refuses to drop a column an index depends on, which is the
		// whole point: the indexes above had to go first.
		if _, err := db.Exec(fmt.Sprintf(`ALTER TABLE %q DROP COLUMN %q`, a.table, a.column)); err != nil {
			t.Fatalf("drop %s.%s to simulate an older database: %v", a.table, a.column, err)
		}
	}
	if _, err := db.Exec(`PRAGMA user_version = 0`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	// The upgrade a real deployment performs.
	st, err = Open(path)
	if err != nil {
		t.Fatalf("upgrading an older database failed: %v", err)
	}
	// Every migrated column is back, and the console can read the settings row
	// through them — a missing column shows up as a scan error, not a zero.
	settings, ok, err := st.GetSettings()
	if err != nil || !ok {
		t.Fatalf("GetSettings after upgrade: ok=%v err=%v", ok, err)
	}
	if settings.RouterLabel != "edge1" {
		t.Errorf("router label = %q, want the pre-upgrade value", settings.RouterLabel)
	}
	if settings.SuricataRulesPath != "/var/lib/suricata/rules/suricata.rules" {
		t.Errorf("a migrated column took no default: %q", settings.SuricataRulesPath)
	}
	if settings.AutoBlockEnabled {
		t.Error("blocking on sight came out of an upgrade switched on")
	}

	// And the data is still there.
	counts, err := st.Summary()
	if err != nil {
		t.Fatal(err)
	}
	if counts.Events != 1 {
		t.Errorf("events after upgrade = %d, want 1", counts.Events)
	}
	if _, err := st.ObservedCategories(10); err != nil {
		t.Errorf("querying a migrated column after upgrade: %v", err)
	}

	// Reopening again must be a no-op, not a second migration.
	st.Close()
	again, err := Open(path)
	if err != nil {
		t.Fatalf("reopening an already-migrated database: %v", err)
	}
	again.Close()
}

// indexNameOf pulls the name out of a CREATE INDEX statement.
func indexNameOf(stmt string) string {
	const marker = "EXISTS "
	i := indexOfSub(stmt, marker)
	if i < 0 {
		return ""
	}
	rest := stmt[i+len(marker):]
	j := indexOfSub(rest, " ")
	if j < 0 {
		return ""
	}
	return rest[:j]
}

func indexOfSub(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
