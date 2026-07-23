#!/bin/sh
# Runs after the package installs meerkat. Creates the service account and its
# state directory, then reloads systemd. It does NOT start meerkat: the operator
# runs "meerkat init" first to create the admin account.
set -e

# Create a system user/group for the service if they don't exist.
if ! getent group meerkat >/dev/null 2>&1; then
	groupadd --system meerkat
fi
if ! getent passwd meerkat >/dev/null 2>&1; then
	useradd --system --gid meerkat --home-dir /var/lib/meerkat \
		--shell /usr/sbin/nologin --comment "meerkat service account" meerkat
fi

# meerkat's whole job is reading Suricata's eve.json, which Debian ships as
# 0640 root:adm. Without this the service starts, finds the file unreadable, and
# looks exactly like a quiet network — so join the group at install time rather
# than leaving it as a step to discover later. "meerkat doctor" checks it too.
if getent group adm >/dev/null 2>&1; then
	usermod -a -G adm meerkat || true
fi

# State directory, owned by the service account. The suricata/ subdirectory is
# the handoff for rule management: meerkat writes the generated filter files and
# a request there, and the privileged meerkat-apply unit reads them, does the
# work as root, and writes the result back. meerkat owns the directory, so it
# can replace a root-written result file even though it cannot write one.
mkdir -p /var/lib/meerkat/suricata
chown -R meerkat:meerkat /var/lib/meerkat
chmod 0750 /var/lib/meerkat

if command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload || true
	# The path unit is what lets an unprivileged console apply a ruleset change
	# at all. Enabling it here rather than leaving it to the operator means the
	# Rules page works out of the box; it does nothing until meerkat asks.
	systemctl enable --now meerkat-apply.path >/dev/null 2>&1 || true
fi

cat <<'EOF'

meerkat installed.

Next steps:
  1. sudo meerkat init          # create the admin account
  2. sudo meerkat doctor        # check eve.json access, geo databases, nftably
  3. sudo systemctl enable --now meerkat

By default meerkat listens on 0.0.0.0:8100 with no TLS. Set the access list
under Settings -> Access control as soon as you log in, or bind it to loopback
(edit the unit's --listen to 127.0.0.1:8100) and reach it over an SSH tunnel.

meerkat never blocks anything itself. To enable the block button, mint an API
token in nftably under Settings -> Automation API and paste it into meerkat
under Settings -> Blocking.
EOF

exit 0
