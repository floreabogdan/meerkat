package store

// schema is meerkat's schema. New tables are added here (all IF NOT EXISTS);
// new columns on existing tables go through migrate().
//
// The shape worth understanding before reading the SQL: `events` is the raw
// alert stream and is disposable — retention prunes it. `sources` is the durable
// ledger and the thing the operator actually works with, so it is maintained
// incrementally as events arrive rather than derived from them on read. That is
// what lets the home page stay fast while a sensor produces 891 alerts in 4 minutes,
// and what lets a source keep its triage state after its events have aged out.
const schema = `
CREATE TABLE IF NOT EXISTS settings (
	id               INTEGER PRIMARY KEY CHECK (id = 1),
	router_label     TEXT NOT NULL DEFAULT '',
	listen_addr      TEXT NOT NULL DEFAULT '0.0.0.0:8100',
	-- IPs/CIDRs allowed to reach meerkat at all — an application-level firewall
	-- in front of the console. Loopback is always allowed and an empty list means
	-- no restriction, so it defaults open and cannot lock out an SSH tunnel.
	access_whitelist TEXT NOT NULL DEFAULT '',

	-- Ingest: the eve.json to follow and where the read offset is remembered.
	eve_path         TEXT NOT NULL DEFAULT '/var/log/suricata/eve.json',
	state_path       TEXT NOT NULL DEFAULT '',

	-- Enrichment. The three database paths are resolved by the server; empty
	-- means "the standard filename inside geoip_dir". geoip_autoupdate is opt-in
	-- and is the only thing that ever makes meerkat reach the network.
	geoip_dir        TEXT NOT NULL DEFAULT '',
	geoip_asn_db     TEXT NOT NULL DEFAULT '',
	geoip_country_db TEXT NOT NULL DEFAULT '',
	geoip_city_db    TEXT NOT NULL DEFAULT '',
	geoip_autoupdate INTEGER NOT NULL DEFAULT 0,

	-- Retention. Events older than retention_days are pruned; max_events is a
	-- backstop for a flood that would otherwise fill the disk inside the window.
	-- A source is pruned with its events only if it was never triaged.
	retention_days   INTEGER NOT NULL DEFAULT 7,
	max_events       INTEGER NOT NULL DEFAULT 2000000,

	-- Where blocks are pushed (Phase 2). Blocking is nftables' job, never
	-- Suricata's: meerkat calls nftably's token-gated POST /api/block.
	nftably_url      TEXT NOT NULL DEFAULT '',
	nftably_token    TEXT NOT NULL DEFAULT '',

	-- Threat-map shipper: batches of alerts POSTed to the public map.
	-- The wire contract is mirrored in the website's src/lib/threats.ts —
	-- change both together.
	threats_enabled  INTEGER NOT NULL DEFAULT 0,
	threats_url      TEXT NOT NULL DEFAULT '',
	threats_token    TEXT NOT NULL DEFAULT '',
	-- The site this router reports as. The map shows destinations as a site
	-- name plus a port and NEVER as a customer address, so this is the only
	-- thing published about our side of a detection.
	site_name        TEXT NOT NULL DEFAULT '',
	site_country     TEXT NOT NULL DEFAULT '',
	site_lat         REAL NOT NULL DEFAULT 0,
	site_lng         REAL NOT NULL DEFAULT 0,
	-- The id of the last event successfully shipped. Persisted so a restart
	-- resumes rather than re-publishing or skipping.
	threats_cursor   INTEGER NOT NULL DEFAULT 0,
	-- Our own address space. A source inside it is a customer or one of our
	-- hosts — an infected internal machine calling out will trip a rule with
	-- OUR address as the source, and publishing that on a public map is exactly
	-- the reconnaissance leak that reporting destinations as a site name exists
	-- to prevent. Sources matching these prefixes are never shipped.
	home_nets        TEXT NOT NULL DEFAULT '',

	-- Managing the sensor's ruleset. The paths are Debian's defaults; the
	-- staging directory is meerkat's own, and is the only one of these the
	-- unprivileged service ever writes.
	suricata_rules_path TEXT NOT NULL DEFAULT '/var/lib/suricata/rules/suricata.rules',
	suricata_conf_dir   TEXT NOT NULL DEFAULT '/etc/suricata',
	suricata_socket     TEXT NOT NULL DEFAULT '/var/run/suricata-command.socket',
	suricata_data_dir   TEXT NOT NULL DEFAULT '/var/lib/suricata',
	-- Fetch a fresh ruleset from the configured sources on a schedule. Off by
	-- default: pulling 52,000 new rules onto a live inline sensor is a change to
	-- what the network does, and it should be a decision.
	rules_auto_update   INTEGER NOT NULL DEFAULT 0,
	rules_update_hour   INTEGER NOT NULL DEFAULT 4,
	rules_last_update   TEXT NOT NULL DEFAULT '',
	-- The master switch for "always block this". Every auto-block is still a
	-- call to nftably and still lands in the actions ledger, and the rate limit
	-- bounds the damage a badly-chosen rule can do.
	autoblock_enabled   INTEGER NOT NULL DEFAULT 0,
	autoblock_max_hour  INTEGER NOT NULL DEFAULT 20,

	-- Theme preferences, kept on the account so they follow the operator across
	-- logins: mode ('' = system | light | dark), accent, and layout density.
	theme_mode       TEXT NOT NULL DEFAULT '',
	-- green is the shared default across meerkat, birdy and nftably.
	theme_accent     TEXT NOT NULL DEFAULT 'green',
	theme_density    TEXT NOT NULL DEFAULT 'comfortable',

	created_at       TEXT NOT NULL,
	updated_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	username      TEXT NOT NULL UNIQUE,
	password_hash TEXT NOT NULL,
	created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
	token      TEXT PRIMARY KEY,
	user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	created_at TEXT NOT NULL,
	expires_at TEXT NOT NULL
);

-- The operator timeline: logins, settings changes, ingest problems. Named
-- "audit" rather than the house "events" because in meerkat an event is a
-- Suricata alert — the domain owns that word.
CREATE TABLE IF NOT EXISTS audit (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	ts         TEXT NOT NULL,
	kind       TEXT NOT NULL,
	actor      TEXT NOT NULL DEFAULT '',
	message    TEXT NOT NULL,
	created_at TEXT NOT NULL
);

-- ── the alert stream ─────────────────────────────────────────────────────
-- One row per Suricata alert. Disposable: retention prunes it, and the rollups
-- below survive that pruning.
--
-- The exact eve.json line is deliberately not stored. At the observed rate that
-- is ~500 MB/day of mostly-duplicate JSON, and the fields that matter for triage
-- are all columns here; the protocol context that varies (HTTP host, TLS SNI,
-- DNS name, SSH banner) goes in the small "extra" JSON blob. eve.json itself is
-- still on disk if the byte-exact record is ever needed.
CREATE TABLE IF NOT EXISTS events (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	ts         TEXT NOT NULL,
	src_ip     TEXT NOT NULL,
	src_port   INTEGER NOT NULL DEFAULT 0,
	dest_ip    TEXT NOT NULL DEFAULT '',
	dest_port  INTEGER NOT NULL DEFAULT 0,
	proto      TEXT NOT NULL DEFAULT '',
	app_proto  TEXT NOT NULL DEFAULT '',
	iface      TEXT NOT NULL DEFAULT '',
	sid        INTEGER NOT NULL DEFAULT 0,
	gid        INTEGER NOT NULL DEFAULT 0,
	rev        INTEGER NOT NULL DEFAULT 0,
	signature  TEXT NOT NULL DEFAULT '',
	category   TEXT NOT NULL DEFAULT '',
	-- Suricata severity: 1 is the most severe, 3 the least. "Worst" is therefore
	-- MIN() everywhere in this schema.
	severity   INTEGER NOT NULL DEFAULT 0,
	-- Suricata's own word for what it did: "allowed" on an alert-only sensor.
	-- meerkat never reports this as "blocked" — only an address actually banned
	-- in nftables is blocked.
	action     TEXT NOT NULL DEFAULT '',
	flow_id    INTEGER NOT NULL DEFAULT 0,
	extra      TEXT NOT NULL DEFAULT ''   -- small JSON: http/tls/dns/ssh context
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_src_ts ON events(src_ip, ts);
CREATE INDEX IF NOT EXISTS idx_events_sid_ts ON events(sid, ts);

-- ── the rollups the console is actually built on ─────────────────────────
-- One row per source address. This is the home page: 891 alerts from a handful
-- of sources, 85% of them one reputation rule restating itself, is not a list to
-- read — it is a handful of sources to triage.
CREATE TABLE IF NOT EXISTS sources (
	ip             TEXT PRIMARY KEY,
	first_seen     TEXT NOT NULL,
	last_seen      TEXT NOT NULL,
	event_count    INTEGER NOT NULL DEFAULT 0,
	-- Denormalised distinct counts, maintained as source_signatures /
	-- source_ports gain rows. Counting them per row on the list page would mean
	-- a correlated subquery over two tables for every source on screen.
	sig_count      INTEGER NOT NULL DEFAULT 0,
	port_count     INTEGER NOT NULL DEFAULT 0,
	worst_severity INTEGER NOT NULL DEFAULT 0,   -- 0 = none recorded yet

	asn            INTEGER NOT NULL DEFAULT 0,
	as_org         TEXT NOT NULL DEFAULT '',
	country        TEXT NOT NULL DEFAULT '',
	country_name   TEXT NOT NULL DEFAULT '',
	continent      TEXT NOT NULL DEFAULT '',
	city           TEXT NOT NULL DEFAULT '',
	-- Coordinates, populated only when a city database is loaded. (0,0) is in
	-- the Atlantic and is what a missed lookup decodes to, so it is treated as
	-- "no position" rather than plotted.
	lat            REAL NOT NULL DEFAULT 0,
	lon            REAL NOT NULL DEFAULT 0,
	-- Private, loopback or CGNAT. Such a source is one of ours: it must never be
	-- blocked on reflex and never leaves the box on the public threat map.
	is_local       INTEGER NOT NULL DEFAULT 0,

	-- Triage state. Only "blocked" claims the address is actually banned in
	-- nftables, and only a confirmed nftably block may set it.
	state          TEXT NOT NULL DEFAULT 'new',  -- new|acknowledged|blocked|allowlisted
	state_note     TEXT NOT NULL DEFAULT '',
	state_at       TEXT NOT NULL DEFAULT '',
	state_by       TEXT NOT NULL DEFAULT '',
	-- When a timed block lapses. nftably's API has no TTL of its own, so meerkat
	-- holds the expiry and issues the unblock itself. Empty means "until
	-- someone unblocks it".
	blocked_until  TEXT NOT NULL DEFAULT '',

	created_at     TEXT NOT NULL,
	updated_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sources_last_seen ON sources(last_seen);
CREATE INDEX IF NOT EXISTS idx_sources_state ON sources(state);
CREATE INDEX IF NOT EXISTS idx_sources_country ON sources(country);
CREATE INDEX IF NOT EXISTS idx_sources_asn ON sources(asn);

-- Which signatures a source tripped, and how often. Backs both the source
-- detail page and the "distinct signatures" column without touching events.
CREATE TABLE IF NOT EXISTS source_signatures (
	ip         TEXT NOT NULL,
	sid        INTEGER NOT NULL,
	hits       INTEGER NOT NULL DEFAULT 0,
	first_seen TEXT NOT NULL,
	last_seen  TEXT NOT NULL,
	PRIMARY KEY (ip, sid)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_source_signatures_sid ON source_signatures(sid);

-- Which destination ports a source touched. proto is part of the key so
-- tcp/80 and udp/80 stay distinct.
CREATE TABLE IF NOT EXISTS source_ports (
	ip         TEXT NOT NULL,
	proto      TEXT NOT NULL,
	port       INTEGER NOT NULL,
	hits       INTEGER NOT NULL DEFAULT 0,
	last_seen  TEXT NOT NULL,
	PRIMARY KEY (ip, proto, port)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_source_ports_port ON source_ports(port);

-- One row per signature ID, with the per-sid disposition. Muting ET CINS —
-- 68.8% of the flood — is meant to be one click (Phase 2 acts on this).
CREATE TABLE IF NOT EXISTS signatures (
	sid          INTEGER PRIMARY KEY,
	gid          INTEGER NOT NULL DEFAULT 0,
	rev          INTEGER NOT NULL DEFAULT 0,
	signature    TEXT NOT NULL DEFAULT '',
	category     TEXT NOT NULL DEFAULT '',
	severity     INTEGER NOT NULL DEFAULT 0,  -- worst seen
	hits         INTEGER NOT NULL DEFAULT 0,
	source_count INTEGER NOT NULL DEFAULT 0,  -- distinct sources that tripped it
	first_seen   TEXT NOT NULL,
	last_seen    TEXT NOT NULL,
	disposition  TEXT NOT NULL DEFAULT 'notify',  -- notify | digest | mute
	-- The ruleset category, derived from the signature's message prefix
	-- ("ET CINS"). The category column above is Suricata's classtype
	-- description ("Misc Attack"), which is a different and much less useful
	-- axis: it puts the reputation feeds and real attacks in the same bucket.
	rule_category TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_signatures_hits ON signatures(hits);
-- NOTE: no index on rule_category here. This file runs BEFORE migrate(), and on
-- an existing database CREATE TABLE IF NOT EXISTS is a no-op — so a column added
-- by a migration does not exist yet at this point, and an index naming it fails
-- the whole schema step. Indexes over migrated columns live in migrate.go.

-- What was done to the network, and by whom. Never mutate a source's state
-- without writing here: this is the record that "blocked" is answerable to.
CREATE TABLE IF NOT EXISTS actions (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	ts         TEXT NOT NULL,
	actor      TEXT NOT NULL DEFAULT '',
	action     TEXT NOT NULL,               -- block|unblock|allowlist|acknowledge|mute|unmute
	target     TEXT NOT NULL,               -- an IP, or "sid:12345"
	ttl_secs   INTEGER NOT NULL DEFAULT 0,  -- 0 = no expiry
	reason     TEXT NOT NULL DEFAULT '',
	result     TEXT NOT NULL DEFAULT '',    -- what the far end said
	ok         INTEGER NOT NULL DEFAULT 1,
	created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_actions_target ON actions(target);

-- ── the ruleset meerkat manages ──────────────────────────────────────────
-- One row per signature in the ruleset Suricata is actually running, rebuilt by
-- an index pass over /var/lib/suricata/rules/suricata.rules.
--
-- This is the catalogue: everything installed, including the ~16,000 rules that
-- ship disabled. the signatures table above is a different thing — the rules that have
-- fired. Joining the two is the point of the whole feature: it is what lets the
-- console sort 52,000 rules by how much noise each one is actually costing,
-- rather than making the operator guess.
CREATE TABLE IF NOT EXISTS rules (
	sid          INTEGER PRIMARY KEY,
	gid          INTEGER NOT NULL DEFAULT 1,
	rev          INTEGER NOT NULL DEFAULT 0,
	-- Read from the rule verbatim. meerkat never writes a drop rule, but it can
	-- be pointed at a sensor somebody else configured, and reporting "alert" for
	-- a rule that says "drop" would be a quiet lie.
	action       TEXT NOT NULL DEFAULT '',
	proto        TEXT NOT NULL DEFAULT '',
	msg          TEXT NOT NULL DEFAULT '',
	-- The message prefix: "ET SCAN", "GPL ICMP", "SURICATA". Not the same thing
	-- as events.category, which is the classtype description Suricata puts in
	-- eve.json ("Misc Attack"). This is the axis an operator has opinions about.
	category     TEXT NOT NULL DEFAULT '',
	classtype    TEXT NOT NULL DEFAULT '',
	priority     INTEGER NOT NULL DEFAULT 0,
	-- Emerging Threats' own metadata rating: Informational|Minor|Major|Critical.
	et_severity  TEXT NOT NULL DEFAULT '',
	rule_created TEXT NOT NULL DEFAULT '',
	rule_updated TEXT NOT NULL DEFAULT '',
	-- Whether the rule is live in the built ruleset. suricata-update writes a
	-- disabled rule as a comment rather than removing it, which is what makes a
	-- disabled rule something the operator can still find and switch back on.
	enabled      INTEGER NOT NULL DEFAULT 0,
	first_seen   TEXT NOT NULL,
	seen_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rules_category ON rules(category);
CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules(enabled);

-- What the operator has decided about a rule or a whole category. Kept separate
-- from the catalogue on purpose: the catalogue is rebuilt wholesale every time the
-- ruleset changes, and a decision must outlive that. A rule that vanishes from
-- ET Open and comes back six months later comes back muted.
CREATE TABLE IF NOT EXISTS rule_policy (
	scope         TEXT NOT NULL,               -- sid | category
	key           TEXT NOT NULL,               -- '2010371' | 'ET CINS'
	-- '' leaves the rule as the ruleset ships it, which is NOT the same as
	-- enabling it: most of ET Open ships disabled and meerkat must never switch
	-- 16,000 rules on by treating "no opinion" as "on".
	state         TEXT NOT NULL DEFAULT '',    -- '' | enabled | disabled
	-- "Always block this." NOT a Suricata drop rule — meerkat pushes the source
	-- to nftably when the rule fires. Suricata here is inline on NFQUEUE and
	-- dropping from it once cost 9.6% of transit traffic.
	autoblock     INTEGER NOT NULL DEFAULT 0,
	autoblock_ttl INTEGER NOT NULL DEFAULT 0,  -- seconds; 0 = until unblocked
	-- Severity meerkat records for this rule's alerts, overriding Suricata's.
	-- 0 = no override. 1 is worst, matching events.severity.
	severity      INTEGER NOT NULL DEFAULT 0,
	note          TEXT NOT NULL DEFAULT '',
	actor         TEXT NOT NULL DEFAULT '',
	created_at    TEXT NOT NULL,
	updated_at    TEXT NOT NULL,
	PRIMARY KEY (scope, key)
) WITHOUT ROWID;

-- Every rule-management run: what was asked for, what suricata-update said, and
-- whether the sensor reloaded. A ruleset change is a change to what the network
-- reports, so it gets the same treatment as a firewall change.
CREATE TABLE IF NOT EXISTS rule_runs (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	started_at    TEXT NOT NULL,
	finished_at   TEXT NOT NULL,
	kind          TEXT NOT NULL,               -- apply | update | index | adopt
	actor         TEXT NOT NULL DEFAULT '',
	reason        TEXT NOT NULL DEFAULT '',
	ok            INTEGER NOT NULL DEFAULT 0,
	step          TEXT NOT NULL DEFAULT '',
	error         TEXT NOT NULL DEFAULT '',
	rules_total   INTEGER NOT NULL DEFAULT 0,
	rules_enabled INTEGER NOT NULL DEFAULT 0,
	added         INTEGER NOT NULL DEFAULT 0,
	removed       INTEGER NOT NULL DEFAULT 0,
	reloaded      INTEGER NOT NULL DEFAULT 0,
	detail        TEXT NOT NULL DEFAULT '',
	log           TEXT NOT NULL DEFAULT '',
	created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rule_runs_started ON rule_runs(started_at);

-- Alert destinations: where meerkat delivers a notification (Phase 3). Copied
-- from the sister projects, which copy it from each other.
CREATE TABLE IF NOT EXISTS alert_destinations (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	name          TEXT NOT NULL UNIQUE,
	type          TEXT NOT NULL,               -- webhook|slack|discord|email|telegram|ntfy|gotify
	enabled       INTEGER NOT NULL DEFAULT 1,
	url           TEXT NOT NULL DEFAULT '',
	smtp_host     TEXT NOT NULL DEFAULT '',
	smtp_port     INTEGER NOT NULL DEFAULT 587,
	smtp_username TEXT NOT NULL DEFAULT '',
	smtp_password TEXT NOT NULL DEFAULT '',
	smtp_from     TEXT NOT NULL DEFAULT '',
	smtp_to       TEXT NOT NULL DEFAULT '',
	smtp_security TEXT NOT NULL DEFAULT 'starttls',
	events        TEXT NOT NULL DEFAULT '',     -- comma-separated kinds; empty = all
	created_at    TEXT NOT NULL,
	updated_at    TEXT NOT NULL
);
`
