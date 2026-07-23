package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/floreabogdan/meerkat/internal/geo"
	"github.com/floreabogdan/meerkat/internal/store"
	"github.com/floreabogdan/meerkat/internal/web"
)

// cmdLookup prints what the configured databases actually produce for an
// address. It exists because enrichment fails silently by design — a database
// that loads but decodes to nothing yields empty fields, not an error — and
// "the country is right but the coordinates are zero" is otherwise only
// visible by reading rows out of SQLite.
func cmdLookup(args []string) error {
	fs := flag.NewFlagSet("lookup", flag.ExitOnError)
	dbPath := fs.String("db", defaultDBPath, "path to meerkat's SQLite database")
	asnDB := fs.String("asn-db", "", "override the ASN database path")
	countryDB := fs.String("country-db", "", "override the country database path")
	cityDB := fs.String("city-db", "", "override the city database path")
	fs.Parse(args)

	if fs.NArg() == 0 {
		return fmt.Errorf("usage: meerkat lookup [flags] <ip> [ip...]")
	}

	asn, country, city := *asnDB, *countryDB, *cityDB
	if asn == "" && country == "" && city == "" {
		if st, err := store.Open(*dbPath); err == nil {
			if settings, ok, err := st.GetSettings(); err == nil && ok {
				asn, country, city = web.ResolveGeoPaths(settings, dirOf(*dbPath))
			}
			st.Close()
		}
	}

	e, err := geo.Open(geo.PathIfExists(asn), geo.PathIfExists(country), geo.PathIfExists(city))
	defer e.Close() //nolint:staticcheck // e is never nil, error or not
	if err != nil {
		fmt.Println("warning:", err)
	}
	fmt.Println("databases:", e.Describes())
	fmt.Println()

	for _, ip := range fs.Args() {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		g := e.Lookup(ip)
		fmt.Printf("%s\n", ip)
		fmt.Printf("  summary     %s\n", g.Describe())
		fmt.Printf("  country     %s (%s)  continent %s\n", orDash(g.Country), orDash(g.CountryName), orDash(g.Continent))
		fmt.Printf("  city        %s\n", orDash(g.City))
		if g.HasCoords() {
			fmt.Printf("  coordinates %.4f, %.4f\n", g.Lat, g.Lon)
		} else {
			fmt.Printf("  coordinates none — this address cannot be plotted on the threat map\n")
		}
		fmt.Printf("  asn         %s %s\n", asnLabel(g.ASN), orDash(g.ASOrg))
		fmt.Printf("  private     %v\n", g.Private)
		fmt.Println()
	}
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func asnLabel(n uint32) string {
	if n == 0 {
		return "—"
	}
	return fmt.Sprintf("AS%d", n)
}
