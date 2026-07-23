package main

import (
	"flag"
	"fmt"

	"github.com/floreabogdan/meerkat/internal/doctor"
	"github.com/floreabogdan/meerkat/internal/shipper"
	"github.com/floreabogdan/meerkat/internal/store"
	"github.com/floreabogdan/meerkat/internal/web"
)

func cmdDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	dbPath := fs.String("db", defaultDBPath, "path to meerkat's SQLite database")
	evePath := fs.String("eve", "", "path to Suricata's eve.json (defaults to the configured value)")
	suricataUnit := fs.String("suricata-unit", defaultSuricataUnit, "systemd unit that runs Suricata")
	fs.Parse(args)

	cfg := doctor.Config{
		DBPath:       *dbPath,
		EvePath:      firstNonEmpty(*evePath, defaultEvePath),
		SuricataUnit: *suricataUnit,
	}

	// Read the stored settings when there are any, so doctor checks what the
	// service will actually use rather than the compiled-in defaults. A database
	// that will not open is itself worth reporting, so this is best-effort.
	if st, err := store.Open(*dbPath); err == nil {
		if settings, ok, err := st.GetSettings(); err == nil && ok {
			if *evePath == "" && settings.EvePath != "" {
				cfg.EvePath = settings.EvePath
			}
			cfg.ASNDB, cfg.CountryDB, cfg.CityDB = web.ResolveGeoPaths(settings, dirOf(*dbPath))
			cfg.NftablyURL, cfg.NftablyToken = settings.NftablyURL, settings.NftablyToken
			cfg.ThreatsEnabled = settings.ThreatsEnabled
			cfg.ThreatsURL, cfg.ThreatsToken = settings.ThreatsURL, settings.ThreatsToken
			cfg.SiteName, cfg.SiteLat, cfg.SiteLng = settings.SiteName, settings.SiteLat, settings.SiteLng
			cfg.HomeNets, _ = shipper.ParseHomeNets(settings.HomeNets)
			paths := suricataPaths(settings, *dbPath)
			cfg.RulesPath, cfg.SuricataSocket = paths.RulesFile, paths.Socket
			cfg.StagingDir = paths.Staging
		}
		st.Close()
	}

	results := doctor.Run(cfg)
	for _, r := range results {
		fmt.Printf("[%-4s] %-20s %s\n", r.Status, r.Name, r.Detail)
	}

	if doctor.Failed(results) {
		fmt.Println("\nOne or more checks failed.")
		return fmt.Errorf("preflight checks failed")
	}
	fmt.Println("\nAll checks passed (or are informational warnings).")
	return nil
}
