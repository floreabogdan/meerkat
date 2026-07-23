// Package geo turns an IP address into who and where it is: ASN, organisation,
// country, and — when a city database is present — a city and coordinates. It
// also owns the local copies of the DB-IP Lite databases, downloading and
// refreshing them itself so meerkat does not depend on another service's data
// directory.
//
// Every lookup is best-effort. A missing database or a miss in one degrades to
// zero values, never an error: an unenriched alert is still an alert.
//
// Lifted from the throwaway predecessor (eve-discord) with its tests, which run
// against the real .mmdb files copied off the router.
package geo

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"

	"github.com/oschwald/maxminddb-golang/v2"
)

// Geo is what we manage to learn about an address. Every field is best-effort;
// a lookup miss yields the zero value rather than an error, because a missing
// country is no reason to withhold an alert.
type Geo struct {
	ASN         uint32
	ASOrg       string
	Country     string // ISO 3166-1 alpha-2
	CountryName string
	Continent   string
	Private     bool

	// City-level fields, populated only when a city database is configured.
	// The threat map needs coordinates to draw an arc; the country database
	// has none, so without a city DB these stay zero and the point is dropped.
	City string
	Lat  float64
	Lon  float64
}

// HasCoords reports whether this lookup yielded a usable map position.
// (0,0) is in the Atlantic and is what a missing lookup decodes to, so it is
// treated as absent rather than plotted.
func (g Geo) HasCoords() bool {
	return g.Lat != 0 || g.Lon != 0
}

func (g Geo) Empty() bool {
	return g.ASN == 0 && g.ASOrg == "" && g.Country == "" && !g.Private
}

// Describe renders the enrichment as one compact line, e.g.
// "🇺🇸 US · AS16509 Amazon.com, Inc.".
func (g Geo) Describe() string {
	if g.Private {
		return "private/local"
	}
	var parts []string
	if g.Country != "" {
		if f := FlagEmoji(g.Country); f != "" {
			parts = append(parts, f+" "+g.Country)
		} else {
			parts = append(parts, g.Country)
		}
	}
	if g.ASN != 0 {
		as := fmt.Sprintf("AS%d", g.ASN)
		if g.ASOrg != "" {
			as += " " + g.ASOrg
		}
		parts = append(parts, as)
	} else if g.ASOrg != "" {
		parts = append(parts, g.ASOrg)
	}
	if len(parts) == 0 {
		return "unknown"
	}
	return strings.Join(parts, " · ")
}

// asnRecord matches DBIP-ASN-Lite, which is GeoLite2-ASN compatible.
type asnRecord struct {
	Number uint32 `maxminddb:"autonomous_system_number"`
	Org    string `maxminddb:"autonomous_system_organization"`
}

// countryRecord matches DBIP-Country-Lite.
type countryRecord struct {
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	Continent struct {
		Code  string            `maxminddb:"code"`
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"continent"`
}

// cityRecord matches DBIP-City-Lite (GeoLite2-City compatible).
type cityRecord struct {
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	Subdivisions []struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
}

// Enricher holds the opened databases and a lookup cache. Safe for concurrent
// use: the ingest loop and the web handlers share one.
type Enricher struct {
	asn     *maxminddb.Reader
	country *maxminddb.Reader
	city    *maxminddb.Reader

	mu    sync.RWMutex
	cache map[netip.Addr]Geo
}

// PathIfExists returns path when a file is actually there, and "" otherwise.
//
// It exists because most of meerkat's database paths are not configuration but
// a guess: "the standard DB-IP filename inside the data directory". A missing
// file at a guessed path means "not installed", which is an ordinary state and
// should read as one. A file that *is* there but will not open is a real fault,
// and Open still reports that loudly.
func PathIfExists(path string) string {
	if path == "" {
		return ""
	}
	if _, err := os.Stat(path); err != nil {
		return ""
	}
	return path
}

// Open opens whichever databases are configured. Any path may be empty or
// unreadable; enrichment degrades to whatever is available, and the error
// describes what could not be opened rather than aborting.
func Open(asnPath, countryPath, cityPath string) (*Enricher, error) {
	e := &Enricher{cache: make(map[netip.Addr]Geo)}
	var errs []string

	open := func(path, label string, dst **maxminddb.Reader) {
		if path == "" {
			return
		}
		r, err := maxminddb.Open(path)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s db %s: %v", label, path, err))
			return
		}
		*dst = r
	}

	open(asnPath, "asn", &e.asn)
	open(countryPath, "country", &e.country)
	open(cityPath, "city", &e.city)

	if len(errs) > 0 {
		return e, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return e, nil
}

func (e *Enricher) Close() {
	for _, r := range []*maxminddb.Reader{e.asn, e.country, e.city} {
		if r != nil {
			r.Close()
		}
	}
}

// Describes reports which databases actually loaded, for the startup log and
// the doctor check.
func (e *Enricher) Describes() string {
	var have []string
	if e.asn != nil {
		have = append(have, "asn:"+e.asn.Metadata.DatabaseType)
	}
	if e.country != nil {
		have = append(have, "country:"+e.country.Metadata.DatabaseType)
	}
	if e.city != nil {
		have = append(have, "city:"+e.city.Metadata.DatabaseType)
	}
	if len(have) == 0 {
		return "none"
	}
	return strings.Join(have, " ")
}

// HasCity reports whether a city database is loaded — i.e. whether lookups can
// carry coordinates.
func (e *Enricher) HasCity() bool { return e != nil && e.city != nil }

const maxCacheEntries = 8192

// Lookup enriches a textual address. An unparseable address yields the zero Geo.
func (e *Enricher) Lookup(ipStr string) Geo {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return Geo{}
	}
	return e.LookupAddr(addr)
}

// LookupAddr enriches an already-parsed address.
func (e *Enricher) LookupAddr(addr netip.Addr) Geo {
	addr = addr.Unmap()

	if IsLocal(addr) {
		return Geo{Private: true}
	}

	e.mu.RLock()
	g, ok := e.cache[addr]
	e.mu.RUnlock()
	if ok {
		return g
	}

	g = e.lookupUncached(addr)

	e.mu.Lock()
	// Scanning traffic churns through addresses; rather than track an LRU for
	// what is only a latency optimisation, drop the whole cache when it grows
	// past the cap.
	if len(e.cache) >= maxCacheEntries {
		e.cache = make(map[netip.Addr]Geo, maxCacheEntries)
	}
	e.cache[addr] = g
	e.mu.Unlock()

	return g
}

func (e *Enricher) lookupUncached(addr netip.Addr) Geo {
	var g Geo

	if e.asn != nil {
		var rec asnRecord
		if res := e.asn.Lookup(addr); res.Found() {
			if err := res.Decode(&rec); err == nil {
				g.ASN = rec.Number
				g.ASOrg = rec.Org
			}
		}
	}

	if e.country != nil {
		var rec countryRecord
		if res := e.country.Lookup(addr); res.Found() {
			if err := res.Decode(&rec); err == nil {
				g.Country = rec.Country.ISOCode
				g.CountryName = rec.Country.Names["en"]
				g.Continent = rec.Continent.Code
			}
		}
	}

	if e.city != nil {
		var rec cityRecord
		if res := e.city.Lookup(addr); res.Found() {
			if err := res.Decode(&rec); err == nil {
				g.City = rec.City.Names["en"]
				g.Lat = rec.Location.Latitude
				g.Lon = rec.Location.Longitude
				// The city database also carries country, which is more
				// specific than the country-only DB when both are present.
				if rec.Country.ISOCode != "" {
					g.Country = rec.Country.ISOCode
					if n := rec.Country.Names["en"]; n != "" {
						g.CountryName = n
					}
				}
				// DB-IP Lite often has no city name but does have a region;
				// a region beats an empty label on the map.
				if g.City == "" && len(rec.Subdivisions) > 0 {
					g.City = rec.Subdivisions[0].Names["en"]
				}
			}
		}
	}

	return g
}

// cgnat is RFC 6598 shared address space: routable-looking but carrier-internal,
// so a geo lookup on it is meaningless.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// IsLocal reports whether an address is private, loopback, link-local, CGNAT or
// otherwise not a real internet host — the addresses a geo lookup cannot answer
// for, and which must never be shipped to a public map.
func IsLocal(addr netip.Addr) bool {
	return addr.IsPrivate() ||
		addr.IsLoopback() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() ||
		addr.IsUnspecified() ||
		addr.IsMulticast() ||
		(addr.Is4() && cgnat.Contains(addr))
}

// FlagEmoji maps an ISO alpha-2 code to its regional indicator pair.
func FlagEmoji(iso string) string {
	if len(iso) != 2 {
		return ""
	}
	iso = strings.ToUpper(iso)
	var r [2]rune
	for i := range 2 {
		c := iso[i]
		if c < 'A' || c > 'Z' {
			return ""
		}
		r[i] = rune(c-'A') + 0x1F1E6
	}
	return string(r[:])
}
