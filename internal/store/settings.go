package store

import (
	"database/sql"
	"fmt"
	"time"
)

// Settings is meerkat's single-row configuration.
type Settings struct {
	RouterLabel string
	ListenAddr  string
	// AccessWhitelist is the IPs/CIDRs allowed to reach meerkat. Loopback is
	// always allowed and an empty list means no restriction, so it defaults open
	// and cannot lock out an SSH tunnel. See access.go.
	AccessWhitelist string

	// EvePath is the Suricata eve.json to follow; StatePath is where the read
	// offset is persisted so a restart resumes rather than replaying or skipping.
	EvePath   string
	StatePath string

	// GeoIPDir holds the .mmdb files. The three explicit paths override the
	// standard filename inside that directory when set.
	GeoIPDir        string
	GeoIPASNDB      string
	GeoIPCountryDB  string
	GeoIPCityDB     string
	GeoIPAutoUpdate bool

	// RetentionDays prunes events by age; MaxEvents is the flood backstop.
	RetentionDays int
	MaxEvents     int64

	// NftablyURL/NftablyToken are where a block is pushed (Phase 2). Blocking is
	// nftables' job, never Suricata's.
	NftablyURL   string
	NftablyToken string

	// Threat-map shipper. The wire contract is mirrored in the website's
	// src/lib/threats.ts — change both together.
	ThreatsEnabled bool
	ThreatsURL     string
	ThreatsToken   string
	SiteName       string
	SiteCountry    string
	SiteLat        float64
	SiteLng        float64
	// ThreatsCursor is the id of the last event successfully shipped.
	ThreatsCursor int64
	// HomeNets are our own prefixes. A source inside them is a customer or one
	// of our hosts and is never published. See schema.go.
	HomeNets string

	// Managing the sensor's ruleset. SuricataStaging is meerkat's own directory
	// and the only one of these the unprivileged service writes; the rest are
	// read, or written by the privileged apply step.
	SuricataRulesPath string
	SuricataConfDir   string
	SuricataSocket    string
	SuricataDataDir   string
	RulesAutoUpdate   bool
	RulesUpdateHour   int
	RulesLastUpdate   time.Time
	// AutoBlockEnabled is the master switch for "always block this". Off by
	// default: a rule that blocks its source on sight is a standing instruction
	// to change the firewall without anybody watching.
	AutoBlockEnabled bool
	AutoBlockMaxHour int

	// Theme preferences, stored on the account so they follow the operator across
	// logins and devices. ThemeMode is "" (follow the system), "light" or "dark";
	// ThemeAccent is ocean|emerald|violet|amber; ThemeDensity is
	// comfortable|compact.
	ThemeMode    string
	ThemeAccent  string
	ThemeDensity string
}

const settingsCols = `router_label, listen_addr, access_whitelist, eve_path, state_path,
	geoip_dir, geoip_asn_db, geoip_country_db, geoip_city_db, geoip_autoupdate,
	retention_days, max_events, nftably_url, nftably_token,
	threats_enabled, threats_url, threats_token, site_name, site_country,
	site_lat, site_lng, threats_cursor, home_nets,
	suricata_rules_path, suricata_conf_dir, suricata_socket, suricata_data_dir,
	rules_auto_update, rules_update_hour, rules_last_update,
	autoblock_enabled, autoblock_max_hour,
	theme_mode, theme_accent, theme_density`

// GetSettings returns the single settings row, or (Settings{}, false, nil) if
// meerkat hasn't been initialized yet.
func (s *Store) GetSettings() (Settings, bool, error) {
	var st Settings
	var lastUpdate string
	row := s.db.QueryRow(`SELECT ` + settingsCols + ` FROM settings WHERE id = 1`)
	err := row.Scan(&st.RouterLabel, &st.ListenAddr, &st.AccessWhitelist, &st.EvePath, &st.StatePath,
		&st.GeoIPDir, &st.GeoIPASNDB, &st.GeoIPCountryDB, &st.GeoIPCityDB, &st.GeoIPAutoUpdate,
		&st.RetentionDays, &st.MaxEvents, &st.NftablyURL, &st.NftablyToken,
		&st.ThreatsEnabled, &st.ThreatsURL, &st.ThreatsToken, &st.SiteName, &st.SiteCountry,
		&st.SiteLat, &st.SiteLng, &st.ThreatsCursor, &st.HomeNets,
		&st.SuricataRulesPath, &st.SuricataConfDir, &st.SuricataSocket, &st.SuricataDataDir,
		&st.RulesAutoUpdate, &st.RulesUpdateHour, &lastUpdate,
		&st.AutoBlockEnabled, &st.AutoBlockMaxHour,
		&st.ThemeMode, &st.ThemeAccent, &st.ThemeDensity)
	if err == sql.ErrNoRows {
		return Settings{}, false, nil
	}
	if err != nil {
		return Settings{}, false, fmt.Errorf("store: get settings: %w", err)
	}
	st.RulesLastUpdate = ParseTime(lastUpdate)
	return st, true, nil
}

// SaveSuricata writes where the sensor's ruleset lives and how meerkat is
// allowed to change it. Like every other form here it owns its own columns, so
// two settings pages cannot clobber each other.
func (s *Store) SaveSuricata(st Settings) error {
	if st.RulesUpdateHour < 0 || st.RulesUpdateHour > 23 {
		return fmt.Errorf("store: the update hour must be 0-23")
	}
	if st.AutoBlockMaxHour < 0 {
		return fmt.Errorf("store: the auto-block rate limit cannot be negative")
	}
	res, err := s.db.Exec(`
		UPDATE settings SET suricata_rules_path = ?, suricata_conf_dir = ?,
			suricata_socket = ?, suricata_data_dir = ?, rules_auto_update = ?,
			rules_update_hour = ?, autoblock_enabled = ?, autoblock_max_hour = ?,
			updated_at = ?
		WHERE id = 1`,
		st.SuricataRulesPath, st.SuricataConfDir, st.SuricataSocket, st.SuricataDataDir,
		st.RulesAutoUpdate, st.RulesUpdateHour, st.AutoBlockEnabled, st.AutoBlockMaxHour,
		now())
	if err != nil {
		return fmt.Errorf("store: save suricata settings: %w", err)
	}
	return notFoundIfZero(res)
}

// SetRulesLastUpdate stamps a successful ruleset fetch. Kept out of
// SaveSuricata for the same reason the shipper's cursor is kept out of
// SaveThreats: editing a setting must not tell the scheduler it already ran.
func (s *Store) SetRulesLastUpdate(t time.Time) error {
	res, err := s.db.Exec(`UPDATE settings SET rules_last_update = ?, updated_at = ? WHERE id = 1`,
		FormatTime(t), now())
	if err != nil {
		return fmt.Errorf("store: set rules last update: %w", err)
	}
	return notFoundIfZero(res)
}

// SaveIdentity writes the settings `meerkat init` establishes and the identity
// form edits. It leaves the access whitelist, ingest and GeoIP fields alone —
// each form owns its own columns so two of them cannot clobber each other.
func (s *Store) SaveIdentity(label, listen string) error {
	ts := now()
	_, err := s.db.Exec(`
		INSERT INTO settings (id, router_label, listen_addr, created_at, updated_at)
		VALUES (1, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			router_label = excluded.router_label,
			listen_addr = excluded.listen_addr,
			updated_at = excluded.updated_at`, label, listen, ts, ts)
	if err != nil {
		return fmt.Errorf("store: save identity: %w", err)
	}
	return nil
}

// SaveIngest writes the ingest and retention settings.
func (s *Store) SaveIngest(evePath, statePath string, retentionDays int, maxEvents int64) error {
	res, err := s.db.Exec(`
		UPDATE settings SET eve_path = ?, state_path = ?, retention_days = ?, max_events = ?, updated_at = ?
		WHERE id = 1`, evePath, statePath, retentionDays, maxEvents, now())
	if err != nil {
		return fmt.Errorf("store: save ingest settings: %w", err)
	}
	return notFoundIfZero(res)
}

// SaveGeoIP writes the enrichment settings.
func (s *Store) SaveGeoIP(dir, asnDB, countryDB, cityDB string, autoUpdate bool) error {
	res, err := s.db.Exec(`
		UPDATE settings SET geoip_dir = ?, geoip_asn_db = ?, geoip_country_db = ?,
			geoip_city_db = ?, geoip_autoupdate = ?, updated_at = ?
		WHERE id = 1`, dir, asnDB, countryDB, cityDB, autoUpdate, now())
	if err != nil {
		return fmt.Errorf("store: save geoip settings: %w", err)
	}
	return notFoundIfZero(res)
}

// SaveNftably writes where blocks are pushed. Phase 2 uses it; Phase 1 only
// checks reachability from `meerkat doctor`.
func (s *Store) SaveNftably(url, token string) error {
	res, err := s.db.Exec(`UPDATE settings SET nftably_url = ?, nftably_token = ?, updated_at = ? WHERE id = 1`,
		url, token, now())
	if err != nil {
		return fmt.Errorf("store: save nftably settings: %w", err)
	}
	return notFoundIfZero(res)
}

// SaveThreats writes the threat-map shipper's configuration. The cursor is
// deliberately not touched here — it is the shipper's own bookmark, and a
// settings save must not rewind or skip published history.
func (s *Store) SaveThreats(st Settings) error {
	res, err := s.db.Exec(`
		UPDATE settings SET threats_enabled = ?, threats_url = ?, threats_token = ?,
			site_name = ?, site_country = ?, site_lat = ?, site_lng = ?, home_nets = ?,
			updated_at = ?
		WHERE id = 1`,
		st.ThreatsEnabled, st.ThreatsURL, st.ThreatsToken, st.SiteName, st.SiteCountry,
		st.SiteLat, st.SiteLng, st.HomeNets, now())
	if err != nil {
		return fmt.Errorf("store: save threats settings: %w", err)
	}
	return notFoundIfZero(res)
}

// SetThreatsCursor advances the shipper's bookmark. Only ever called after a
// batch has actually been accepted by the collector.
func (s *Store) SetThreatsCursor(id int64) error {
	res, err := s.db.Exec(`UPDATE settings SET threats_cursor = ?, updated_at = ? WHERE id = 1`, id, now())
	if err != nil {
		return fmt.Errorf("store: set threats cursor: %w", err)
	}
	return notFoundIfZero(res)
}

// SaveAccessWhitelist writes the IP allow-list.
func (s *Store) SaveAccessWhitelist(list string) error {
	res, err := s.db.Exec(`UPDATE settings SET access_whitelist = ?, updated_at = ? WHERE id = 1`, list, now())
	if err != nil {
		return fmt.Errorf("store: save access whitelist: %w", err)
	}
	return notFoundIfZero(res)
}

// SaveTheme writes the operator's look preferences.
func (s *Store) SaveTheme(mode, accent, density string) error {
	res, err := s.db.Exec(`UPDATE settings SET theme_mode = ?, theme_accent = ?, theme_density = ?, updated_at = ? WHERE id = 1`,
		mode, accent, density, now())
	if err != nil {
		return fmt.Errorf("store: save theme: %w", err)
	}
	return notFoundIfZero(res)
}
