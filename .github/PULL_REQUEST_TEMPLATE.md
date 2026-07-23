<!-- Thanks for the PR. Keep it focused — one logical change. See CONTRIBUTING.md. -->

## What and why

<!-- What does this change, and what problem does it solve? Link any issue (Fixes #N). -->

## Checklist

- [ ] `gofmt -l .` prints nothing, `go vet ./...` and `golangci-lint run` pass
- [ ] `go test -race ./...` passes; behaviour changes come with tests
- [ ] No new dependency, or the PR justifies it (`modernc.org/sqlite` stays — no cgo)
- [ ] Templates carry no inline `style=` or `<script>` (the CSP drops them silently)
- [ ] Nothing weakens the four settled decisions: Suricata stays alert-only, blocking
      goes through nftables, the threat map carries no customer addresses, and
      "detected" and "blocked" still mean what they say
- [ ] No secrets logged or rendered to the browser

<!-- By contributing you agree your work is released under the project's 0BSD license. -->
