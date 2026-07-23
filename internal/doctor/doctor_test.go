package doctor

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func find(t *testing.T, results []Result, name string) Result {
	t.Helper()
	for _, r := range results {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("no check named %q in %+v", name, results)
	return Result{}
}

func TestRunReturnsEveryCheckEvenWhenNothingIsConfigured(t *testing.T) {
	results := Run(Config{DBPath: filepath.Join(t.TempDir(), "meerkat.db")})
	if len(results) < 6 {
		t.Fatalf("got %d checks, want at least 6", len(results))
	}
	for _, r := range results {
		if r.Name == "" || r.Detail == "" {
			t.Errorf("check with no name or detail: %+v", r)
		}
	}
}

// A missing eve.json is an ordinary state (Suricata is
// stopped), so it must warn rather than fail — meerkat waits for the file.
func TestMissingEveJSONWarnsRatherThanFails(t *testing.T) {
	r := find(t, Run(Config{
		EvePath: filepath.Join(t.TempDir(), "nope", "eve.json"),
		DBPath:  filepath.Join(t.TempDir(), "meerkat.db"),
	}), "eve.json readable")
	if r.Status != Warn {
		t.Errorf("status = %v, want Warn: %s", r.Status, r.Detail)
	}
}

func TestReadableEveJSONPasses(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")
	line := `{"timestamp":"2026-07-21T10:00:00.000000+0300","event_type":"alert","src_ip":"198.51.100.7"}` + "\n"
	if err := os.WriteFile(path, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	results := Run(Config{EvePath: path, DBPath: filepath.Join(dir, "meerkat.db")})

	if r := find(t, results, "eve.json readable"); r.Status != OK {
		t.Errorf("readable: %v — %s", r.Status, r.Detail)
	}
	fresh := find(t, results, "eve.json fresh")
	if fresh.Status != OK {
		t.Errorf("fresh: %v — %s", fresh.Status, fresh.Detail)
	}
	if !strings.Contains(fresh.Detail, "alert") {
		t.Errorf("the newest record's type should be reported: %s", fresh.Detail)
	}
}

// A file that exists but is not JSON lines is a real misconfiguration (pointed
// at fast.log, say) and must not read as healthy.
func TestNonEveFileIsFlagged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fast.log")
	if err := os.WriteFile(path, []byte("07/21/2026-10:00:00 [**] [1:2001219:3] ET SCAN [**]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := find(t, Run(Config{EvePath: path, DBPath: filepath.Join(dir, "meerkat.db")}), "eve.json fresh")
	if r.Status != Warn {
		t.Errorf("status = %v, want Warn: %s", r.Status, r.Detail)
	}
}

func TestStaleEveJSONWarns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")
	if err := os.WriteFile(path, []byte(`{"event_type":"alert"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-25 * time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	r := find(t, Run(Config{EvePath: path, DBPath: filepath.Join(dir, "meerkat.db")}), "eve.json fresh")
	if r.Status != Warn {
		t.Errorf("status = %v, want Warn: %s", r.Status, r.Detail)
	}
}

func TestGeoIPChecks(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "meerkat.db")

	t.Run("unconfigured warns", func(t *testing.T) {
		r := find(t, Run(Config{DBPath: dbPath}), "geoip databases")
		if r.Status != Warn {
			t.Errorf("status = %v, want Warn", r.Status)
		}
	})

	t.Run("real databases pass", func(t *testing.T) {
		asn := "../geo/testdata/dbip-asn-lite.mmdb"
		country := "../geo/testdata/dbip-country-lite.mmdb"
		if _, err := os.Stat(asn); err != nil {
			t.Skip("no geo testdata")
		}
		r := find(t, Run(Config{DBPath: dbPath, ASNDB: asn, CountryDB: country}), "geoip databases")
		if r.Status != OK {
			t.Errorf("status = %v: %s", r.Status, r.Detail)
		}
		if !strings.Contains(r.Detail, "city") {
			t.Errorf("the absence of a city database should be called out: %s", r.Detail)
		}
	})

	t.Run("unreadable database warns", func(t *testing.T) {
		r := find(t, Run(Config{DBPath: dbPath, ASNDB: "/nonexistent/asn.mmdb"}), "geoip databases")
		if r.Status != Warn {
			t.Errorf("status = %v, want Warn (enrichment is never a prerequisite)", r.Status)
		}
	})
}

func TestNftablyChecks(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "meerkat.db")

	t.Run("unconfigured warns", func(t *testing.T) {
		r := find(t, Run(Config{DBPath: dbPath}), "nftably reachable")
		if r.Status != Warn {
			t.Errorf("status = %v, want Warn", r.Status)
		}
	})

	// The common half-configured state: nftably is running, but no token has been
	// minted, so the API is off. The message has to name that fix.
	t.Run("url without token warns and names the fix", func(t *testing.T) {
		r := find(t, Run(Config{DBPath: dbPath, NftablyURL: "http://127.0.0.1:8099"}), "nftably reachable")
		if r.Status != Warn {
			t.Errorf("status = %v, want Warn", r.Status)
		}
		if !strings.Contains(r.Detail, "Automation API") {
			t.Errorf("detail should say where to mint the token: %s", r.Detail)
		}
	})

	t.Run("authorised probe passes", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer secret" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if r.URL.Path != "/api/blocked" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"blocked":[{"ip":"198.51.100.7","note":"scanning"}]}`))
		}))
		defer srv.Close()

		r := find(t, Run(Config{DBPath: dbPath, NftablyURL: srv.URL, NftablyToken: "secret"}), "nftably reachable")
		if r.Status != OK {
			t.Errorf("status = %v: %s", r.Status, r.Detail)
		}
		if !strings.Contains(r.Detail, "1 address") {
			t.Errorf("should report the current block count: %s", r.Detail)
		}
	})

	t.Run("bad token fails", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer srv.Close()
		r := find(t, Run(Config{DBPath: dbPath, NftablyURL: srv.URL, NftablyToken: "wrong"}), "nftably reachable")
		if r.Status != Fail {
			t.Errorf("status = %v, want Fail", r.Status)
		}
	})

	// nftably answers 404 (not 401) while its API is disabled, so the message
	// for that case must not read as "wrong token".
	t.Run("api disabled fails with the right explanation", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()
		r := find(t, Run(Config{DBPath: dbPath, NftablyURL: srv.URL, NftablyToken: "any"}), "nftably reachable")
		if r.Status != Fail {
			t.Errorf("status = %v, want Fail", r.Status)
		}
		if !strings.Contains(r.Detail, "disabled") {
			t.Errorf("detail should explain the 404 means the API is off: %s", r.Detail)
		}
	})

	t.Run("unreachable fails", func(t *testing.T) {
		r := find(t, Run(Config{DBPath: dbPath, NftablyURL: "http://127.0.0.1:1", NftablyToken: "x"}), "nftably reachable")
		if r.Status != Fail {
			t.Errorf("status = %v, want Fail", r.Status)
		}
	})
}

func TestDatabasePathCheck(t *testing.T) {
	dir := t.TempDir()
	r := find(t, Run(Config{DBPath: filepath.Join(dir, "sub", "meerkat.db")}), "database path")
	if r.Status != OK {
		t.Errorf("status = %v: %s", r.Status, r.Detail)
	}
	if _, err := os.Stat(filepath.Join(dir, "sub")); err != nil {
		t.Errorf("the data directory should have been created: %v", err)
	}
}

func TestFailed(t *testing.T) {
	if Failed([]Result{{Status: OK}, {Status: Warn}}) {
		t.Error("warnings are not failures")
	}
	if !Failed([]Result{{Status: OK}, {Status: Fail}}) {
		t.Error("a failure should be reported")
	}
}

func TestHumanBytes(t *testing.T) {
	for in, want := range map[int64]string{
		0: "0 B", 512: "512 B", 1024: "1.0 KB", 1536: "1.5 KB", 1 << 30: "1.0 GB",
	} {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestThreatMapChecks(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "meerkat.db")
	nets := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	base := Config{
		DBPath: dbPath, ThreatsEnabled: true,
		ThreatsURL: "https://threats.example.net/api/threats/ingest", ThreatsToken: "t",
		SiteName: "Example Site", SiteLat: 44.86, SiteLng: 24.87, HomeNets: nets,
	}

	t.Run("off is fine", func(t *testing.T) {
		if r := find(t, Run(Config{DBPath: dbPath}), "threat map"); r.Status != OK {
			t.Errorf("status = %v: %s", r.Status, r.Detail)
		}
	})

	t.Run("fully configured passes", func(t *testing.T) {
		if r := find(t, Run(base), "threat map"); r.Status != OK {
			t.Errorf("status = %v: %s", r.Status, r.Detail)
		}
	})

	// Publishing to a site at (0,0) draws every arc into the Atlantic, and the
	// collector has no way to notice.
	t.Run("missing coordinates fails", func(t *testing.T) {
		c := base
		c.SiteLat, c.SiteLng = 0, 0
		r := find(t, Run(c), "threat map")
		if r.Status != Fail || !strings.Contains(r.Detail, "coordinates") {
			t.Errorf("status = %v: %s", r.Status, r.Detail)
		}
	})

	// The one that would leak customer addresses.
	t.Run("no home networks fails", func(t *testing.T) {
		c := base
		c.HomeNets = nil
		r := find(t, Run(c), "threat map")
		if r.Status != Fail {
			t.Errorf("status = %v, want Fail: %s", r.Status, r.Detail)
		}
	})

	t.Run("missing token fails", func(t *testing.T) {
		c := base
		c.ThreatsToken = ""
		if r := find(t, Run(c), "threat map"); r.Status != Fail {
			t.Errorf("status = %v, want Fail", r.Status)
		}
	})

	// The ingest token is a bearer credential; over plain HTTP it is readable
	// by anything on the path.
	t.Run("plain http warns", func(t *testing.T) {
		c := base
		c.ThreatsURL = "http://threats.example.net/api/threats/ingest"
		r := find(t, Run(c), "threat map")
		if r.Status != Warn || !strings.Contains(r.Detail, "clear") {
			t.Errorf("status = %v: %s", r.Status, r.Detail)
		}
	})

	t.Run("malformed url fails", func(t *testing.T) {
		c := base
		c.ThreatsURL = "not a url"
		if r := find(t, Run(c), "threat map"); r.Status != Fail {
			t.Errorf("status = %v, want Fail", r.Status)
		}
	})
}
