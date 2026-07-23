# Changelog

All notable changes to meerkat are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-07-23

First public release. meerkat follows Suricata's `eve.json`, enriches every alert
with ASN, country and city, and rolls it all up per **source address** — because a
sensor producing 891 alerts in four minutes from a few dozen hosts has not given
you 891 things to read, it has given you a few dozen decisions to make.

It covers ingest and the console, blocking through nftables, publishing to a
public threat map, and managing Suricata's own ruleset. Notifications are the
remaining piece; see `PLAN.md`.

### Added

Managing the sensor, not just reading it. meerkat can change which rules Suricata
runs, without anyone editing a file on the router.

- **Rule catalogue.** The whole installed ruleset — 68,005 rules on the reference sensor,
  52,069 of them enabled — parsed from the file Suricata actually loaded and
  joined to what each rule has cost. That join is the point: Suricata knows it
  has 52,000 rules, meerkat knows which of them have fired and how often, and
  sorting by the second turns "which of these should I turn off" from a guess
  into a reading. On the reference sensor the loudest rule of all 68,005 is `GPL ICMP PING *NIX`
  with 82,549 alerts.
- **Categories** — the message prefix (`ET CINS`, `GPL ICMP`), which is the
  axis people actually have opinions about. Turning one off writes a single
  filter rather than a hundred. Note this is *not* eve.json's `category` field:
  that is the classtype description, which files a reputation-list hit and a
  real intrusion under the same "Misc Attack".
- **Enable / disable**, per rule or per category, with a reason that is written
  into `/etc/suricata/disable.conf` as a comment — so the file explains itself
  to someone reading it over SSH who has never heard of meerkat.
- **Severity override** per rule or category, applied as alerts arrive, so
  "ICMP is noise, score it 4" takes effect without touching the sensor.
- **Block on sight.** A rule can be marked so that any source tripping it is
  pushed to nftably automatically. It is *not* a Suricata drop rule and cannot
  become one — Suricata is inline on NFQUEUE here, and dropping from it once
  cost 9.6% of transit traffic. Auto-blocks go through the same call, the same
  refusals and the same ledger as a click, with `auto` as the actor. Off by
  default, rate-limited per hour, and never applied to a private, loopback or
  CGNAT source.
- **Scheduled ruleset updates** — a daily `suricata-update` at a chosen hour,
  off by default, because pulling 52,000 new rules onto a live inline sensor is
  a change to what the network does.
- **Live reload.** A rebuilt ruleset reaches the running sensor over Suricata's
  control socket, verified live: same PID, same start time, `last_reload`
  moved. Restarting an inline IDS is a traffic event; a reload is not.
- **Drift, for rules.** After every apply the built ruleset is re-read from disk
  and each decision is compared against what the sensor actually holds — the
  same way a block is reconciled against nftables rather than remembered. It
  found something on its first run: a rule someone had put in `disable.conf`
  was still enabled, and had been for a day.
- **Adoption.** Filters already in `/etc/suricata` are imported on first run and
  the original file is kept as `.pre-meerkat`. From the first apply onwards
  meerkat's generated file is the whole truth, so anything not carried across
  would have been silently switched back on.
- **`meerkat rules`** — `status`, `index`, `apply` — and **`meerkat passwd`**,
  because a console with local accounts and no reset path means a forgotten
  password needs a database editor.
- Two new `doctor` checks: can the ruleset be read and parsed, and can a change
  actually reach the sensor (suricata-update present, staging writable,
  `meerkat-apply.path` installed, control socket reachable).

The privileged half is deliberately tiny. meerkat's console holds no
capabilities and cannot write `/etc/suricata`, run suricata-update, or open a
root-owned socket. It renders the filter files into its own state directory and
leaves a request; a systemd path unit starts a root oneshot that does four
mechanical steps and writes back what happened. No sudoers entry, no relaxed
`NoNewPrivileges`, no long-running root daemon, and nothing in the privileged
step makes a decision.

Phase 2 — acting on what you find.

- **Block button**, with a reason and an optional expiry (1 hour to 30 days).
  A block is an authenticated call to nftably's `POST /api/block`; meerkat never
  touches netfilter itself. A source is marked `blocked` only after that call
  succeeds, and a failure is written to the ledger rather than swallowed.
  nftably's API has no TTL of its own, so meerkat holds the clock and issues the
  unblock when a timed block lapses.
- **Reconciliation.** Every two minutes meerkat compares what it claims against
  nftably's actual blacklist and corrects itself — in both directions, and never
  the firewall. An address removed by hand stops reading as blocked; one added
  by hand starts. Each correction is recorded, so a state that changed without
  anyone asking can still be explained.
- **Unblock, acknowledge, allowlist**, and **bulk actions** from the sources
  list (capped at 50 — each one is a separate firewall call). A partly-failed
  bulk action reports both halves rather than rounding up to success.
- **Private sources cannot be blocked.** A private, loopback or CGNAT source is
  one of ours; blocking it at the edge would be a self-inflicted outage, so it
  is refused with an explanation rather than warned about.
- **Signatures page** with per-rule dispositions (notify / digest / mute).
  Muting changes what interrupts you, never what is recorded — a muted rule
  still appears in the console and in each source's history, because that is
  exactly what someone needs to read after an incident.
- **Actions ledger** on every source page: who did what, why, and what nftably
  said, including the attempts that failed.

Phase 4 — publishing to the threat map (built ahead of Phase 3, on request).

- **Threat-map shipper**: batches gzipped to the collector's ingest endpoint,
  reading forward from a cursor persisted in the database so a restart neither
  re-publishes history nor skips what arrived while it was down. A failed POST
  holds the cursor and retries.
- Three rules enforced in code, each with a test: the destination address is
  never on the wire (the payload has no field for one), a source inside our own
  networks is never published, and `blocked` is only ever claimed for an address
  actually banned in nftables.
- `meerkat lookup <ip>` — prints what the geo databases produce for an address,
  including "coordinates none", which is how a silent enrichment gap gets found.

Phase 1 — ingest, enrich, store, and the sources console.

- **Ingest.** Follows Suricata's `eve.json` with full `tail -F` semantics:
  rotation, in-place truncation, the file not existing yet, records written
  across two syscalls, and oversized lines. The read offset is persisted via
  temp-file-plus-rename, so a restart neither replays the file nor skips what
  arrived while meerkat was down. Non-alert records are rejected without a JSON
  decode — on a busy sensor they are 98.5% of the file.
- **Enrichment.** ASN, organisation, country, city and coordinates from local
  MaxMind-format databases, with a lookup cache and correct handling of private,
  loopback, link-local and CGNAT addresses. Optional monthly DB-IP Lite
  download, validated before it replaces a working database.
- **Per-source rollups.** `sources`, `source_signatures` and `source_ports` are
  maintained incrementally as alerts arrive, so the console stays fast under a
  flood and a source keeps its triage state after its individual alerts have
  aged out.
- **Sources console** as the home page: filter by free text, country, AS,
  destination port, signature, severity, state, time window and minimum volume;
  sort by any column; server-side paging with a numbered pager and a
  rows-per-page control.
- **Source detail**: activity sparkline, signatures tripped, destination ports,
  geo/AS identity, the individual alerts with their protocol context, and the
  ledger of actions taken.
- **Live tail** with a polled JSON endpoint, a follow toggle, and a bounded row
  count so a flood cannot grow the DOM without limit.
- **Retention** by age plus a hard event cap as a flood backstop. Untriaged
  sources age out with their alerts; acknowledged, blocked and allowlisted ones
  do not.
- **`meerkat doctor`**: is `eve.json` present, readable and fresh; is its newest
  record parseable; is Suricata running; are the geo databases loaded and
  actually decoding; is nftably reachable and its API token accepted; is the
  database writable.
- **Packaging**: `.deb`/`.rpm`/`.apk` via nfpm, a hardened systemd unit that
  runs unprivileged with no capabilities, and a static Docker image.

### Fixed

- **The rule parser lost eight rules of 67,983**, two of them enabled, with no
  error anywhere — the only visible symptom was the console's enabled count
  sitting two below Suricata's own. A rule option's value may contain an
  unescaped double quote (ET Open ships `pcre:"/^["']?post/Ri"`), and splitting
  options on semicolons-outside-quotes desynchronises there and swallows the
  rest of the rule including its sid. Suricata's real grammar ignores quotes
  and ends an option at the first semicolon that is not backslash-escaped.
  meerkat now parses all 67,983.
- **Every rule reload failed** with an unexplained EOF. Suricata's control
  protocol is newline-terminated and meerkat was not sending the terminator, so
  the sensor waited for a message that never completed and hung up. The reason
  it presented as a mystery rather than a protocol error is that the handshake
  reply was never checked; it is now, and a refused version says so.
- **A stopped Suricata reported as running.** Its socket file survives the
  process, mode bit and all, so stat-ing the path is not a liveness check. It
  now connects — and tells apart "no socket" (stopped), "nothing listening"
  (died), and "not allowed to open it", which is the normal state for the
  unprivileged console and says nothing about the sensor's health.
- **`/\evil.example` was an open redirect** in the `back` parameter every form
  uses. Browsers normalise a backslash in the authority to a slash, so it is
  fetched as `//evil.example` — a host, not a path.
- An index on a column added by a migration was in `schema.go`, which runs
  *before* migrations. Fresh databases were fine and every existing one failed
  to open. There is now a test that walks a real upgrade.
- `card-success` had no stylesheet rule, so every "that worked" banner rendered
  identically to a failure.

### Changed

- The home page is now a **dashboard** (volume over time, loudest rules,
  category and country breakdowns, busiest sources); the sources list moved to
  `/sources` and is purely the triage surface. Mixing summary tiles above a
  filter bar made both jobs worse.
- The look now matches **birdy** exactly — same stylesheet, tokens, type scale
  and theming mechanics, including the pre-paint theme bootstrap and the
  browser-held compact toggle. The density axis was dropped from the account
  settings to match; it is a per-screen choice.

### Notes

- Suricata is treated as alert-only throughout. Each alert shows its own verdict
  verbatim, which on this deployment is always `allowed`; dropping is nftables'
  job, so only a source's state says whether anything is actually being blocked.
  See the README for why.

[Unreleased]: https://github.com/floreabogdan/meerkat/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/floreabogdan/meerkat/releases/tag/v0.1.0
