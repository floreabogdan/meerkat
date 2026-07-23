package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/floreabogdan/meerkat/internal/buildinfo"
	"github.com/floreabogdan/meerkat/internal/geo"
	"github.com/floreabogdan/meerkat/internal/ingest"
	"github.com/floreabogdan/meerkat/internal/nftably"
	"github.com/floreabogdan/meerkat/internal/rules"
	"github.com/floreabogdan/meerkat/internal/shipper"
	"github.com/floreabogdan/meerkat/internal/store"
	"github.com/floreabogdan/meerkat/internal/suricata"
	"github.com/floreabogdan/meerkat/internal/triage"
	"github.com/floreabogdan/meerkat/internal/web"
)

func cmdServer(args []string) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	dbPath := fs.String("db", defaultDBPath, "path to meerkat's SQLite database")
	listen := fs.String("listen", "", "override listen address (defaults to the value set by \"meerkat init\")")
	evePath := fs.String("eve", "", "override the eve.json path (defaults to the value set by \"meerkat init\")")
	fromStart := fs.Bool("from-start", false, "read the whole eve.json instead of resuming where meerkat left off")
	tlsCert := fs.String("tls-cert", "", "PEM certificate file for native HTTPS (requires --tls-key)")
	tlsKey := fs.String("tls-key", "", "PEM private key file for native HTTPS (requires --tls-cert)")
	fs.Parse(args)
	if (*tlsCert == "") != (*tlsKey == "") {
		return fmt.Errorf("--tls-cert and --tls-key must be provided together")
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	st, err := store.Open(*dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer st.Close()

	// Refuse to run half-broken: an unwritable database would otherwise only
	// fail at the first login, with an opaque "internal error".
	if err := st.CheckWritable(); err != nil {
		return fmt.Errorf(`the database at %s is not writable by the user meerkat runs as: %w

This usually means "meerkat init" ran as root while the service runs as the meerkat user.
Fix it with:

  sudo chown -R meerkat:meerkat %s`, *dbPath, err, filepath.Dir(*dbPath))
	}

	settings, ok, err := st.GetSettings()
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("meerkat has not been initialized — run \"meerkat init\" first")
	}

	dataDir := filepath.Dir(*dbPath)
	effListen := firstNonEmpty(*listen, settings.ListenAddr, defaultListen)
	effEve := firstNonEmpty(*evePath, settings.EvePath, defaultEvePath)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Refresh the geo databases before opening them, so a first run on a clean
	// box comes up enriched rather than degraded. Opt-in, and never fatal.
	asnPath, countryPath, cityPath := web.ResolveGeoPaths(settings, dataDir)
	if settings.GeoIPAutoUpdate {
		dir := settings.GeoIPDir
		if dir == "" {
			dir = dataDir
		}
		updater := geo.NewUpdater(dir, "meerkat/"+buildinfo.Version, log)
		ensureCtx, cancel := context.WithTimeout(ctx, 20*time.Minute)
		if err := updater.Ensure(ensureCtx, []geo.Kind{geo.KindASN, geo.KindCountry, geo.KindCity}, geoMaxAge); err != nil {
			log.Warn("geoip databases incomplete, continuing with what is available", "err", err)
		}
		cancel()
	}

	// Only open what is actually there: these paths are mostly a guess at a
	// standard filename, so a missing file means "not installed", not an error.
	enricher, err := geo.Open(geo.PathIfExists(asnPath), geo.PathIfExists(countryPath), geo.PathIfExists(cityPath))
	if err != nil {
		// Geo data is an enhancement, not a prerequisite: still ingest.
		log.Warn("a geoip database is present but unreadable; sources may have no country or ASN", "err", err)
	}
	defer enricher.Close()

	if settings.StatePath != "" {
		if err := os.MkdirAll(filepath.Dir(settings.StatePath), 0o750); err != nil {
			log.Warn("cannot create the read-offset directory; restarts will resume at the end of eve.json", "err", err)
			settings.StatePath = ""
		}
	}

	// Blocking. meerkat never touches netfilter itself: a block is an
	// authenticated call to nftably, which owns that decision. The manager also
	// reconciles in the background, so "blocked" stays a verified claim rather
	// than a memory of a call made an hour ago.
	nft := nftably.New(settings.NftablyURL, settings.NftablyToken, "meerkat/"+buildinfo.Version)
	tri := triage.New(st, nft, log)

	// The auto-blocker acts on rules the operator marked "always block". It is
	// wired into ingest as a reactor, so it also carries the per-signature
	// severity overrides, which apply as alerts are written.
	auto := triage.NewAuto(tri, st, log)

	var wg sync.WaitGroup

	in := ingest.New(ingest.Config{
		Store:     st,
		Geo:       enricher,
		Log:       log,
		Reactions: auto,
		EvePath:   effEve,
		StatePath: settings.StatePath,
		FromStart: *fromStart,
		Retention: time.Duration(settings.RetentionDays) * 24 * time.Hour,
		MaxEvents: settings.MaxEvents,
	})

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := in.Run(ctx); err != nil {
			log.Error("ingest stopped", "err", err)
		}
	}()

	// Managing Suricata's ruleset: the catalogue of what is installed, the
	// policy over it, and the handoff to the privileged step that applies a
	// change. Started before the console so /rules has a catalogue to show.
	ruleMgr := rules.New(rules.Config{Store: st, Paths: suricataPaths(settings, *dbPath), Log: log})
	if n, err := st.BackfillRuleCategories(suricata.CategoryOf); err != nil {
		log.Warn("could not backfill signature categories", "err", err)
	} else if n > 0 {
		log.Info("backfilled the ruleset category on stored signatures", "signatures", n)
	}
	// Adoption runs once, and only when meerkat has no policy of its own: from
	// the first apply onwards meerkat's generated disable.conf is the whole
	// truth, so anything already in /etc/suricata has to be carried across or
	// it would be silently switched back on.
	if adopted, unsupported, err := ruleMgr.Adopt("meerkat"); err != nil {
		log.Warn("could not adopt existing suricata rule filters", "err", err)
	} else if adopted > 0 || len(unsupported) > 0 {
		log.Info("adopted existing suricata rule filters", "adopted", adopted, "unsupported", len(unsupported))
		for _, line := range unsupported {
			log.Warn("a filter in /etc/suricata cannot be represented in meerkat and will be lost on the next apply", "line", line)
		}
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		ruleMgr.Run(ctx)
	}()

	// The threat-map publisher, when it is turned on and fully configured. It
	// reads forward from a cursor in the database, so it is independent of the
	// ingest pipeline and survives a restart without re-publishing history.
	var ship *shipper.Shipper
	if settings.ThreatsEnabled && settings.ThreatsURL != "" && settings.ThreatsToken != "" {
		homeNets, errs := shipper.ParseHomeNets(settings.HomeNets)
		if len(errs) > 0 {
			// Refuse to publish rather than publish too much: a malformed
			// exclusion list is exactly how a customer address ends up public.
			log.Error("threat map publishing is disabled: the 'our networks' list does not parse",
				"errors", strings.Join(errs, "; "))
		} else {
			ship = shipper.New(shipper.Config{
				Store: st,
				Log:   log,
				URL:   settings.ThreatsURL,
				Token: settings.ThreatsToken,
				Site: shipper.Site{
					Name: settings.SiteName, Country: settings.SiteCountry,
					Lat: settings.SiteLat, Lng: settings.SiteLng,
				},
				HomeNets:  homeNets,
				UserAgent: "meerkat/" + buildinfo.Version,
			})
			// A publisher that has never run starts at "now": replaying a full
			// retention window onto a public map on first enable would be a
			// surprise, and the map wants live traffic, not history.
			if settings.ThreatsCursor == 0 {
				if newest, err := st.HighestShippableID(); err == nil && newest > 0 {
					if err := st.SetThreatsCursor(newest); err != nil {
						log.Warn("could not set the initial threat-map cursor", "err", err)
					} else {
						log.Info("threat map publishing starts from now", "from_event", newest)
					}
				}
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				ship.Run(ctx)
			}()
		}
	}

	if nft.Configured() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tri.Run(ctx)
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			auto.Run(ctx)
		}()
		log.Info("blocking enabled", "nftably", settings.NftablyURL)
	} else {
		log.Info("blocking is not configured; set nftably's URL and API token under Settings")
	}

	srv := web.New(web.Config{
		Store:      st,
		Geo:        enricher,
		Ingest:     in,
		Shipper:    ship,
		Triage:     tri,
		Auto:       auto,
		Rules:      ruleMgr,
		Log:        log,
		ListenAddr: effListen,
		DataDir:    dataDir,
	})

	// Said once, at startup: meerkat binds every interface by default, so an
	// allow-all access list means anyone who finds the port reaches the login —
	// and without TLS, the login crosses the network in the clear.
	if srv.WideOpen() {
		if *tlsCert == "" {
			log.Warn("meerkat is reachable from any IP and has no TLS — set the access list under Settings → Access control, configure --tls-cert/--tls-key, or bind loopback with --listen 127.0.0.1:8100",
				"addr", effListen)
		} else {
			log.Warn("meerkat is reachable from any IP — narrow the access list under Settings → Access control",
				"addr", effListen)
		}
	}

	// Bound connection lifetimes prevent a small number of slow clients from
	// exhausting the server's file descriptors or goroutines.
	httpServer := &http.Server{
		Addr:              effListen,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}
	errCh := make(chan error, 1)
	go func() {
		log.Info("meerkat listening", "addr", effListen, "tls", *tlsCert != "", "eve", effEve,
			"geoip", enricher.Describes(), "retention_days", settings.RetentionDays)
		var err error
		if *tlsCert != "" {
			err = httpServer.ListenAndServeTLS(*tlsCert, *tlsKey)
		} else {
			err = httpServer.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-errCh:
		return err
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	shutdownErr := httpServer.Shutdown(shutdownCtx)

	// Wait for ingest to drain: it holds alerts already read from eve.json whose
	// offset has been recorded, so abandoning them here would lose them for good.
	wg.Wait()
	return shutdownErr
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func dirOf(path string) string { return filepath.Dir(path) }
