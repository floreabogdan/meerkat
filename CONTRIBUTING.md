# Contributing to meerkat

Thanks for your interest. meerkat is a personal project released in the hope it
is useful to someone else. Issues and pull requests are welcome — and, as the
README says, may be ignored or declined. Please read this first so we don't
waste each other's time.

## Before you start

meerkat is **deliberately narrow**: one sensor's `eve.json`, rolled up per source
address, on the router itself. It is not a SIEM, it does not correlate across
sensors, it does not ship logs anywhere, and it will not make Suricata drop
packets. If your change adds a knob, a dependency, or surface area, **open an
issue first** and describe the use case. A small change that fits the existing
grain is far more likely to land than a large one that broadens the scope. It's
0BSD, so forking is free.

## Building

```sh
go build ./cmd/meerkat
go test -race ./...     # the whole suite, under the race detector
gofmt -l .              # must print nothing
go vet ./...            # must pass
golangci-lint run       # if you have it; CI runs it
govulncheck ./...       # known-vulnerability scan; CI runs it
```

CI runs exactly these and will reject a red build. It also cross-compiles to
linux/{amd64,arm64,arm}, freebsd and darwin, and builds and installs the `.deb`.

Go 1.25+. There is no frontend build step and no code generation — what is in
the repo is what runs.

`modernc.org/sqlite` is a hard requirement: it is pure Go, so meerkat
cross-compiles to a router with `CGO_ENABLED=0` and no toolchain on the far end.
Do not swap in `mattn/go-sqlite3`.

## Layout

| Package | What it owns |
| --- | --- |
| `cmd/meerkat` | the `init` / `doctor` / `server` / `version` subcommands |
| `internal/eve` | reading `eve.json`: the tailer and the record decoder |
| `internal/geo` | IP → ASN/country/city, and the DB-IP downloader |
| `internal/ingest` | the pipeline: tail → prefilter → decode → enrich → batch → store |
| `internal/store` | the schema, migrations, and every query |
| `internal/web` | handlers, templates and static assets |
| `internal/doctor` | the preflight checks |
| `internal/notify` | multi-channel alert delivery (shared with birdy and nftably) |

`internal/notify` is deliberately duplicated across the three sister projects
rather than factored into a shared module. Improve it here and port the change,
as nftably and birdy do between themselves.

## Testing

Tests run against real data wherever possible. `internal/eve/evetest` embeds 386
alerts captured from a live router, and `internal/geo/testdata` holds the actual
`.mmdb` files production reads — so a database layout change that silently
breaks every lookup fails a test instead of shipping.

Read `internal/eve/evetest/evetest.go` before drawing conclusions from that
fixture: it predates a `HOME_NET` correction and does **not** contain the
reputation-list flood described in the README.

Some conventions worth knowing:

- **Timestamps are fixed-width.** Every stored time uses `store.TimeFormat`,
  because `MIN()`/`MAX()`/`ORDER BY` compare these columns as TEXT.
  `time.RFC3339Nano` trims trailing zeros and would sort an event half a second
  later *before* one on the whole second. There is a regression test.
- **No inline `style=` or `<script>` in templates.** The CSP sets
  `style-src 'self'; script-src 'self'` with no `unsafe-inline`, so an inline
  style is silently dropped by the browser while every server-side test passes.
  Proportional graphics use `<progress value max>` or SVG geometry attributes.
  `TestNoInlineStyleInTemplates` and `TestNoInlineScriptInTemplates` enforce it.
- **Every page has a render test.** A Go template is only compiled when it is
  executed, so an untested page ships with its typos.

## The four settled decisions

Suricata stays alert-only; blocking goes through nftables and never Suricata;
the public threat map never carries customer addresses; and `detected` and
`blocked` mean exactly what they say. Each came out of a measurement, and the
README explains which. Reversing one needs better evidence than the original,
not a preference.

## Screenshots

`internal/web/preview_test.go` is the harness behind `docs/screenshots/*.png`. It
seeds a database, serves the **real** console over it, and drives headless Chrome
across the pages — so a screenshot cannot drift from what the product renders.
Regenerate them when the UI changes:

```sh
MEERKAT_PREVIEW=/usr/bin/chromium MEERKAT_PREVIEW_OUT=docs/screenshots \
  go test ./internal/web -run TestPreview -v
```

It is skipped unless `MEERKAT_PREVIEW` is set, so it never runs in CI. Every
address in the seed is documentation space (RFC 5737 / RFC 3849) and every AS
number is from RFC 5398's documentation range; keep it that way.

## Style

Match the surrounding code. Comments explain *why* — a constant that looks
arbitrary, a branch that looks redundant, an ordering that matters — and skip
what the code already says.

## Pull requests

- Branch from `main`, keep the PR focused, and write a clear description of the
  problem and the fix. One logical change per PR.
- By contributing you agree your work is released under the project's
  [0BSD license](LICENSE) — public-domain-equivalent, no attribution required.
  No CLA, no sign-off needed.

## Security

Please do **not** file security issues in public. See [SECURITY.md](SECURITY.md).
