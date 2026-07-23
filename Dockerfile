# syntax=docker/dockerfile:1

# ── build ────────────────────────────────────────────────────────────────
FROM golang:1.26-alpine AS build
WORKDIR /src

# Cache modules first.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=0.1.0-dev
# CGO stays off — modernc.org/sqlite is pure Go, so the binary is static and
# needs nothing from the final image to run.
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags="-s -w -X github.com/floreabogdan/meerkat/internal/buildinfo.Version=${VERSION}" \
      -o /out/meerkat ./cmd/meerkat

# ── runtime ──────────────────────────────────────────────────────────────
FROM alpine:3.20
# ca-certificates: the opt-in DB-IP GeoIP download is the only thing meerkat
# ever fetches, and it is HTTPS-only.
RUN apk add --no-cache ca-certificates \
 && addgroup -S meerkat \
 && adduser -S -G meerkat -H -h /var/lib/meerkat meerkat \
 && mkdir -p /var/lib/meerkat \
 && chown meerkat:meerkat /var/lib/meerkat

COPY --from=build /out/meerkat /usr/bin/meerkat

VOLUME /var/lib/meerkat
EXPOSE 8100
# NOTE: meerkat needs to READ the host's eve.json, so mount it read-only and
# make sure the file is readable by the container's meerkat user (uid varies —
# --user root, or match the host's adm gid with --group-add). Run init first to
# create the admin account:
#
#   docker run --rm -it -v meerkat-data:/var/lib/meerkat meerkat init
#   docker run -d -p 8100:8100 \
#     -v meerkat-data:/var/lib/meerkat \
#     -v /var/log/suricata/eve.json:/var/log/suricata/eve.json:ro \
#     meerkat
USER meerkat
ENTRYPOINT ["meerkat"]
CMD ["server", "--listen", "0.0.0.0:8100"]
