#!/bin/sh
# Build meerkat's .deb / .rpm / .apk packages for each Linux arch, into ./dist.
# Usage: deploy/build-packages.sh [VERSION]   (VERSION defaults to $VERSION or a dev string)
#
# Pure Go + nfpm, so it needs no Debian build environment and runs the same
# locally and in CI. Run from the repo root.
set -e

VERSION="${1:-${VERSION:-0.0.0-dev}}"
VERSION="${VERSION#v}" # nfpm wants a bare semver; the binary keeps the v below
NFPM="${NFPM:-nfpm}"

mkdir -p dist
LDFLAGS="-s -w -X github.com/floreabogdan/meerkat/internal/buildinfo.Version=v${VERSION}"
# The commit is stamped when the caller knows it (CI passes it; a local build
# falls back to git, and to nothing outside a checkout).
COMMIT="${COMMIT:-$(git rev-parse HEAD 2>/dev/null || true)}"
if [ -n "$COMMIT" ]; then
	LDFLAGS="$LDFLAGS -X github.com/floreabogdan/meerkat/internal/buildinfo.Commit=${COMMIT}"
fi

# The packaged unit points at /usr/bin (Debian policy for packaged binaries),
# unlike the manual-install unit which uses /usr/local/bin.
sed 's#/usr/local/bin/meerkat#/usr/bin/meerkat#' deploy/meerkat.service > dist/meerkat.service
sed 's#/usr/local/bin/meerkat#/usr/bin/meerkat#' deploy/meerkat-apply.service > dist/meerkat-apply.service

# GOARCH:GOARM:nfpm-arch. nfpm maps its arch to each packager's convention.
for triple in amd64::amd64 arm64::arm64 arm:7:arm7; do
	goarch=$(echo "$triple" | cut -d: -f1)
	goarm=$(echo "$triple" | cut -d: -f2)
	pkgarch=$(echo "$triple" | cut -d: -f3)

	echo "building linux/$goarch ($pkgarch)"
	CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" GOARM="$goarm" \
		go build -trimpath -ldflags="$LDFLAGS" -o dist/meerkat ./cmd/meerkat

	for pkg in deb rpm apk; do
		ARCH="$pkgarch" VERSION="$VERSION" "$NFPM" package -f nfpm.yaml -p "$pkg" -t dist/
	done
done

rm -f dist/meerkat dist/meerkat.service dist/meerkat-apply.service
echo "--- packages ---"
ls -1 dist/*.deb dist/*.rpm dist/*.apk 2>/dev/null || true
