# meerkat — plan

A Suricata console for an edge router: ingest `eve.json`, enrich it,
make it searchable, and let an operator act on what they find — including
pushing a block into nftables with one click.

Named for *Suricata suricatta*, the meerkat: the sentry that stands watch and
alarm-calls. Follows the house pattern — `birdy` ← BIRD, `nftably` ← nftables,
`meerkat` ← Suricata.

Status: **not started.** This plan is the handoff from the session that built
the throwaway predecessor (`eve-discord`) and diagnosed the sensor.

---

## Why this exists

Suricata produces enormous volumes of low-value events and a handful of things
that matter. Measured live: **891 alerts in 4 minutes**, of which

| share | category | what it is |
| --- | --- | --- |
| 68.8% | ET CINS | "source is on a reputation list" |
| 16.3% | ET DROP | Dshield blocklist, same idea |
| 10.6% | GPL ICMP | someone pinging |
| 2.6% | SURICATA | engine events (invalid ack, checksums) |
| **1.4%** | **ET SCAN** | **actual scanning** |
| **0.3%** | **ET COMPROMISED** | **actual compromise indicator** |

Piping that to Discord was tried and flooded the channel in minutes. The lesson
is not "filter harder" — it is that **a chat channel is the wrong tool**. What is
needed is a console: search, group, triage, act.

## Non-negotiables

These were settled with real evidence; do not quietly reverse them.

1. **Suricata stays alert-only.** It runs inline on NFQUEUE 0 (nftably's Posture
   page installs `queue flags bypass to 0` in the forward chain). Left at
   defaults it dropped **258,101 of 2,676,291 packets — 9.6%** of transit, not
   from rules but from `exception-policy: auto` resolving to drop-flow. Blocking
   is nftables' job, not Suricata's. The predecessor's notes have the four
   config knobs that enforce this.
2. **Blocking goes through nftably**, via its token-gated `POST /api/block`
   (`internal/web/api.go:handleAPIBlock` in nftably). It adds the address to
   the `blacklist` named set and pushes it to the live kernel set immediately.
   nftably's README names this as the intended seam: *"wire up your own detection
   and let nftably do the dropping."*
3. **The public threat map never shows customer IPs.** Destinations are reported
   as a site name ("Example Site") plus port. See the website's `THREAT-MAP.md`.
4. **`detected` vs `blocked` must stay honest.** An alert is `detected`. Only an
   address actually banned in nftables is `blocked`.

## House conventions (from nftably / birdy)

- Module `github.com/floreabogdan/meerkat`, Go 1.25+.
- Layout: `cmd/meerkat/{main,init,server,doctor,defaults}.go`, `internal/…`.
- Subcommands: `init` (create db + admin), `server`, `doctor`, `version`.
- **SQLite via `modernc.org/sqlite`** — pure Go, no cgo, cross-compiles clean.
  (Do *not* use mattn/go-sqlite3.)
- `internal/store` owns schema + migrations (`schema.go`, `migrate.go`).
- `internal/web` owns handlers + `templates/` + `static/`, server-rendered HTML
  with small vanilla JS. No SPA framework.
- `internal/notify` — the multi-channel dispatcher (webhook, Slack, Discord,
  email, Telegram, ntfy, Gotify) exists in both nftably and birdy. **Copy it**;
  they already copy it from each other (`notify.go` says "Adapted from the sister
  project birdy").
- `internal/buildinfo`, `internal/doctor` — same pattern.
- Packaging: `nfpm.yaml` for the .deb, `deploy/` for systemd units, `Dockerfile`,
  `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md`, `docs/screenshots/`.
- Auth: `golang.org/x/crypto` bcrypt + server-side sessions, as nftably does.

## Architecture

One binary per router. It tails locally, stores locally, serves its own UI, and
optionally forwards upstream.

```
                       ┌──────────────────── meerkat (per router) ───────────────────┐
/var/log/suricata/  →  │ tail → parse → enrich (ASN/country/city) → store (sqlite)   │
      eve.json         │                                │                            │
                       │                    ┌───────────┼───────────┬──────────────┐ │
                       │                    ▼           ▼           ▼              ▼ │
                       │                 web UI     notifier    threat-map    nftably│
                       │              search/triage  (Discord)   shipper      /api/  │
                       │               BLOCK button              (threats.example.net)   block │
                       └─────────────────────────────────────────────────────────────┘
```

## Data model

The central idea that makes this a console rather than a log viewer: **events
roll up into `sources`**, and triage happens on sources, not rows.

- `events` — one row per alert. Indexed on `(ts)`, `(src_ip, ts)`, `(sid, ts)`.
  Retention window, pruned on a schedule.
- `sources` — one row per source IP: first/last seen, total events, distinct
  signatures, distinct destination ports, worst severity, ASN/country/city,
  current state (`new` / `acknowledged` / `blocked` / `allowlisted`).
  This is what the operator actually looks at and acts on.
- `signatures` — sid → text, category, count, and a per-sid `disposition`
  (`notify` / `digest` / `mute`). Muting ET CINS should be one click.
- `actions` — audit log: who blocked/unblocked/allowlisted what, when, why.
  Never mutate silently; this is the record of what was done to the network.
- `settings`, `sessions`, `alert_destinations` — as nftably.

## Features, in priority order

**Phase 1 — see it**
- Tail + parse + enrich + store; retention; `doctor` checks (eve.json readable,
  Suricata running, geo DBs present, nftably reachable).
- Sources view: sortable, filterable (country, ASN, port, signature, severity,
  time, state). This is the home page, not the raw event list.
- Source detail: timeline, which signatures, which ports, geo/ASN, raw events.
- Live tail view.

**Phase 2 — act on it**
- **Block button** → `POST /api/block` on nftably, with optional TTL, reason,
  and a confirm step. Record in `actions`. Show current state.
- Unblock; allowlist (never alert on this source again).
- Per-signature disposition: mute / digest / notify.
- Bulk actions from the sources list (block all from AS X in the last hour).

**Phase 3 — tell me**
- `internal/notify` wired to source-level thresholds, not per-event: "a source
  crossed 50 events across 5 signatures", "a new ET COMPROMISED fired".
  Digest for the reputation bulk.
- Dashboard: top sources/countries/ports/signatures, 24h timeline.

**Phase 4 — publish**
- Threat-map shipper: batch + gzip + `POST /api/threats/ingest` to
  `threats.example.net`. Contract mirrored in the website's `src/lib/threats.ts` —
  **mirrored, keep in sync**.
- Optional: accept ingest *from* other meerkats, so one can act as the console
  for a fleet.

**Phase 5 — manage it** *(built)*
- Rule catalogue read from the ruleset Suricata actually loaded, joined to
  observed volume so the noisy rules sort to the top.
- Enable/disable per rule or per category, severity overrides, and
  block-on-sight (through nftably, never as a Suricata drop rule).
- `suricata-update` driven from the console, scheduled or on demand, with a
  live reload over Suricata's control socket.
- Drift: after every apply the built ruleset is re-read and each decision
  compared against what the sensor holds.
- The privileged half is a systemd path unit plus a root oneshot; the console
  keeps zero capabilities. See the README.

**Later**
- Correlation rules (same source hitting N sites → incident).
- PCAP pivot, if Suricata is configured to write them.
- Prometheus `/metrics`, as nftably has.

## Reuse from the predecessor

That project is a throwaway prototype but its hard parts are tested and should be
lifted, not rewritten:

| File | Why it's worth keeping |
| --- | --- |
| `tail.go` | `tail -F` semantics: rotation, truncation, partial lines, offset persisted via temp+rename, oversized-line handling. Tests cover all of it, race-clean on Linux. |
| `eve.go` | `eventTypeOf()` rejects a line without JSON-decoding it — matters when 98.5% of a 1.1 GB file is `flow` records. |
| `enrich.go` | ASN/country/city lookup + caching + private/CGNAT handling. |
| `geoip.go` | Self-managed DB-IP Lite downloads: monthly, previous-month fallback, https-only redirects, validate-then-rename. |
| `shipper.go` | Batch + gzip + retry to the threat map. |
| `dedup.go`, `discord.go` | Dedup windows and Discord embed/rate-limit handling. |

Tests live alongside; bring them. `testdata/` has 386 real alerts captured from
a live sensor plus the real mmdb files — genuinely useful fixtures.

**Retire the predecessor once meerkat runs.** It is installed on the same box
as a systemd service and does the same job far worse.
