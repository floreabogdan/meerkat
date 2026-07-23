package main

import "time"

const (
	defaultDBPath = "/var/lib/meerkat/meerkat.db"

	// meerkat binds every interface so a fresh install is reachable without
	// editing anything. It has no TLS and its access list starts as allow-all,
	// so the UI says so until Settings → Access control narrows it. Bind loopback
	// with --listen 127.0.0.1:8100 (plus an SSH tunnel) for the closed posture.
	//
	// Port 8100 keeps meerkat out of the way of its sister projects on the same
	// router: birdy owns 8080 and nftably owns 8099.
	defaultListen = "0.0.0.0:8100"

	// defaultEvePath is Suricata's default JSON log location on Debian.
	defaultEvePath = "/var/log/suricata/eve.json"

	// defaultSuricataUnit is the systemd unit doctor asks about.
	defaultSuricataUnit = "suricata"

	// defaultRetentionDays bounds the stored alert history. A busy sensor can
	// produce ~300k alerts a day, so a week is already a large table; the
	// per-source rollups are what survive beyond it.
	defaultRetentionDays = 7

	// defaultMaxEvents is the flood backstop, applied when a burst would fill
	// the disk well inside the retention window.
	defaultMaxEvents = 2_000_000

	// geoMaxAge is how stale a DB-IP Lite database may get before the opt-in
	// updater refreshes it. They are published monthly.
	geoMaxAge = 30 * 24 * time.Hour
)
