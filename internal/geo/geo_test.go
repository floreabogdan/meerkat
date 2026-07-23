package geo

import (
	"os"
	"strings"
	"testing"
)

// openTestEnricher loads the databases copied from the router. These are the
// exact files production reads, so a schema mismatch shows up here.
func openTestEnricher(t *testing.T) *Enricher {
	t.Helper()
	asn := "testdata/dbip-asn-lite.mmdb"
	country := "testdata/dbip-country-lite.mmdb"
	for _, p := range []string{asn, country} {
		if _, err := os.Stat(p); err != nil {
			t.Skipf("missing %s: %v", p, err)
		}
	}
	e, err := Open(asn, country, "")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(e.Close)
	return e
}

func TestEnricherDatabaseTypes(t *testing.T) {
	e := openTestEnricher(t)
	desc := e.Describes()
	// If DB-IP ever changes the layout, the struct tags stop matching and
	// every lookup silently returns zeroes; assert on the declared type.
	if !strings.Contains(desc, "ASN") {
		t.Errorf("asn database type unexpected: %s", desc)
	}
	if !strings.Contains(desc, "Country") {
		t.Errorf("country database type unexpected: %s", desc)
	}
	t.Logf("loaded: %s", desc)
}

func TestEnricherKnownAddresses(t *testing.T) {
	e := openTestEnricher(t)

	// The only real addresses anywhere in this repo, and they have to be real:
	// a known-answer test against a real GeoIP database cannot use documentation
	// space, which by design is in no database. All three are globally published
	// anycast or cloud addresses that say nothing about anybody's network.
	tests := []struct {
		ip          string
		wantASN     uint32
		wantCountry string
		orgContains string
	}{
		{ip: "8.8.8.8", wantASN: 15169, wantCountry: "US", orgContains: "GOOGLE"},
		{ip: "1.1.1.1", wantASN: 13335, orgContains: "CLOUDFLARE"},
		{ip: "18.190.15.50", wantASN: 16509, wantCountry: "US", orgContains: "AMAZON"},
	}

	for _, tc := range tests {
		t.Run(tc.ip, func(t *testing.T) {
			g := e.Lookup(tc.ip)
			if g.Private {
				t.Fatalf("%s classified as private", tc.ip)
			}
			if tc.wantASN != 0 && g.ASN != tc.wantASN {
				t.Errorf("ASN = %d, want %d", g.ASN, tc.wantASN)
			}
			if tc.wantCountry != "" && g.Country != tc.wantCountry {
				t.Errorf("country = %q, want %q", g.Country, tc.wantCountry)
			}
			if tc.orgContains != "" && !strings.Contains(strings.ToUpper(g.ASOrg), tc.orgContains) {
				t.Errorf("org = %q, want it to contain %q", g.ASOrg, tc.orgContains)
			}
			t.Logf("%s -> %s", tc.ip, g.Describe())
		})
	}
}

func TestEnricherIPv6(t *testing.T) {
	e := openTestEnricher(t)
	g := e.Lookup("2001:4860:4860::8888") // Google public DNS
	if g.ASN != 15169 {
		t.Errorf("IPv6 ASN = %d, want 15169 (%s)", g.ASN, g.Describe())
	}
}

// An IPv4 address written in IPv4-mapped IPv6 form must resolve identically;
// otherwise every lookup on such an address silently misses.
func TestEnricherUnmapsIPv4MappedAddresses(t *testing.T) {
	e := openTestEnricher(t)
	plain := e.Lookup("8.8.8.8")
	mapped := e.Lookup("::ffff:8.8.8.8")
	if plain.ASN != mapped.ASN || plain.Country != mapped.Country {
		t.Errorf("mapped form differs: %+v vs %+v", plain, mapped)
	}
}

func TestEnricherPrivateAddresses(t *testing.T) {
	e := openTestEnricher(t)
	for _, ip := range []string{
		"10.0.0.1", "192.168.1.1", "172.16.5.4",
		"127.0.0.1", "::1", "169.254.1.1", "0.0.0.0",
		"100.64.0.1", // CGNAT
		"224.0.0.1",  // multicast
	} {
		g := e.Lookup(ip)
		if !g.Private {
			t.Errorf("%s should be treated as local, got %+v", ip, g)
		}
		if g.Describe() != "private/local" {
			t.Errorf("%s describes as %q", ip, g.Describe())
		}
	}
}

func TestEnricherHandlesBadInput(t *testing.T) {
	e := openTestEnricher(t)
	for _, ip := range []string{"", "not-an-ip", "999.999.999.999", "1.2.3"} {
		g := e.Lookup(ip)
		if !g.Empty() {
			t.Errorf("%q produced %+v, want empty", ip, g)
		}
		if g.Describe() != "unknown" {
			t.Errorf("%q describes as %q", ip, g.Describe())
		}
	}
}

// Enrichment must not be a hard dependency: a missing database degrades to
// unenriched alerts rather than stopping ingest.
func TestEnricherMissingDatabasesStillUsable(t *testing.T) {
	e, err := Open("testdata/nope.mmdb", "testdata/also-nope.mmdb", "")
	if err == nil {
		t.Fatal("expected an error describing the missing databases")
	}
	defer e.Close()

	if got := e.Describes(); got != "none" {
		t.Errorf("Describes() = %q", got)
	}
	// Lookups must still be safe to call.
	if g := e.Lookup("8.8.8.8"); !g.Empty() {
		t.Errorf("expected empty result, got %+v", g)
	}
	if g := e.Lookup("10.0.0.1"); !g.Private {
		t.Error("private detection should work without databases")
	}
}

func TestEnricherCacheReturnsConsistentResults(t *testing.T) {
	e := openTestEnricher(t)
	first := e.Lookup("8.8.8.8")
	second := e.Lookup("8.8.8.8") // served from cache
	if first != second {
		t.Errorf("cache changed the answer: %+v vs %+v", first, second)
	}
}

// The country-only database has no coordinates, so nothing enriched by it may
// claim a map position — the threat map drops such points rather than plotting
// them in the Atlantic.
func TestNoCityDatabaseMeansNoCoordinates(t *testing.T) {
	e := openTestEnricher(t)
	if e.HasCity() {
		t.Skip("a city database is present in testdata")
	}
	if g := e.Lookup("8.8.8.8"); g.HasCoords() {
		t.Errorf("got coordinates without a city database: %+v", g)
	}
}

func TestFlagEmoji(t *testing.T) {
	tests := map[string]string{
		"US":  "\U0001F1FA\U0001F1F8",
		"RO":  "\U0001F1F7\U0001F1F4",
		"us":  "\U0001F1FA\U0001F1F8", // case-insensitive
		"":    "",
		"U":   "",
		"USA": "",
		"1A":  "",
	}
	for in, want := range tests {
		if got := FlagEmoji(in); got != want {
			t.Errorf("FlagEmoji(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGeoDescribe(t *testing.T) {
	tests := []struct {
		name string
		g    Geo
		want string
	}{
		{"full", Geo{ASN: 15169, ASOrg: "GOOGLE", Country: "US"}, "\U0001F1FA\U0001F1F8 US · AS15169 GOOGLE"},
		{"asn only", Geo{ASN: 15169, ASOrg: "GOOGLE"}, "AS15169 GOOGLE"},
		{"country only", Geo{Country: "RO"}, "\U0001F1F7\U0001F1F4 RO"},
		{"private", Geo{Private: true}, "private/local"},
		{"empty", Geo{}, "unknown"},
		{"org without asn", Geo{ASOrg: "Some ISP"}, "Some ISP"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.g.Describe(); got != tc.want {
				t.Errorf("Describe() = %q, want %q", got, tc.want)
			}
		})
	}
}
