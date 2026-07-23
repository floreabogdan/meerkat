# Security policy

## Reporting a vulnerability

Email **ixsplit@gmail.com** with "meerkat" in the subject. Please include what
you found, how to reproduce it, and what an attacker gets out of it. Expect an
acknowledgement within a few days.

Please do not open a public issue for anything exploitable until there is a fix.

## What meerkat is exposed to

meerkat parses hostile input by design: `eve.json` is a record of what attackers
are doing, and the signature names, addresses and protocol fields in it are
attacker-influenced. Assume every field is untrusted.

- The tailer is bounded — an oversized line is dropped without desynchronising
  the stream — and the record decoder is `encoding/json` against a fixed struct.
- Everything rendered from an alert is escaped by `html/template`; there is a
  test that feeds a `<script>` tag through as a signature name and an AS
  organisation and checks it comes back escaped on every page that shows it.
- The console is behind a login, and behind an IP allow-list in front of that.

## Deployment posture

Out of the box meerkat binds `0.0.0.0:8100` and has **no TLS**, so a fresh
install is reachable by anyone who can route to the port and the login crosses
the network in the clear. This is a deliberate trade for a first run that works
without editing anything, and the UI says so on the console and in the startup
log. Close it with one of:

- Settings → Access control — an IP/CIDR allow-list. A client outside it has its
  connection closed rather than being served a 403, so a scanner cannot tell
  there is a service listening. Loopback is always allowed, so this cannot lock
  you out of an SSH tunnel.
- `--listen 127.0.0.1:8100` plus an SSH tunnel.
- `--tls-cert` / `--tls-key` for native HTTPS (TLS 1.2 minimum).

## What is stored

meerkat's SQLite database holds the admin password hash, session tokens, the
nftably API token, and the full alert history. Treat it as a secret; it is
excluded from git by `.gitignore`, and the systemd unit keeps its directory 0750
and owned by the service account.

- Passwords are bcrypt at the default cost.
- Session tokens are 32 bytes of CSPRNG output, stored only as their SHA-256
  hash, so a database read does not yield usable bearer tokens.
- The nftably API token is stored as-is, because it has to be replayed to
  nftably. It is never rendered back into the settings form.

## Privilege

The service account holds **no Linux capabilities**. It reads `eve.json` through
group membership (`adm`) and reaches nftably over HTTP. The unit sets
`NoNewPrivileges`, `ProtectSystem=strict`, `PrivateDevices`,
`MemoryDenyWriteExecute` and a restricted address-family set.

meerkat cannot change the firewall itself. A block is an authenticated HTTP call
to nftably, which owns that decision — so compromising meerkat does not directly
grant the ability to alter netfilter, and every attempt is recorded in the
actions ledger.

## Outbound network

meerkat makes exactly two kinds of outbound request:

1. The **opt-in** monthly DB-IP Lite GeoIP download over HTTPS. It refuses any
   redirect to plaintext, caps the decompressed size, and validates the file as
   a real database before it replaces a working one. Off by default.
2. Blocking calls to the nftably URL you configure.

GeoIP *lookups* are entirely local and never leave the box.
