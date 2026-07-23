#!/bin/sh
# Runs before the package is removed. Stop and disable the service so it is not
# left running against files that are about to disappear.
set -e

if command -v systemctl >/dev/null 2>&1; then
	systemctl stop meerkat.service || true
	systemctl disable meerkat.service || true
	systemctl stop meerkat-apply.path || true
	systemctl disable meerkat-apply.path || true
fi

exit 0
