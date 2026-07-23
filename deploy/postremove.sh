#!/bin/sh
# Runs after the package is removed. Reload systemd so the now-absent unit is
# forgotten. The service account and /var/lib/meerkat (which holds the admin
# login, the settings, and the whole triage history — every source someone
# blocked or allowlisted) are deliberately left in place, so an upgrade or
# reinstall keeps working; remove them by hand for a full purge:
#
#   sudo userdel meerkat && sudo rm -rf /var/lib/meerkat
set -e

if command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload || true
fi

exit 0
