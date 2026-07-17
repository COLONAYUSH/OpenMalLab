# mal-web image: the read-only analyst console front door.
#
# Static Go binary on scratch, non-root. The console (services/mal-web/web) is
# embedded into the binary at build time, so the image is fully self-contained
# and serves offline with no external assets. It holds no credentials, parses
# no hostile bytes, and only serves static files and reverse-proxies the read
# API to the gateway.

FROM golang:1.26-alpine AS build

# Optional corporate TLS interception CA for the build stage only; see
# deploy/certs/README.md. Nothing from this survives into the runtime image.
COPY deploy/certs/ /tmp/extra-certs/
RUN cat /tmp/extra-certs/*.pem >> /etc/ssl/certs/ca-certificates.crt 2>/dev/null || true

WORKDIR /src
COPY go.mod go.sum ./
COPY internal/ internal/
COPY services/mal-web/ services/mal-web/
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /mal-web ./services/mal-web

FROM scratch
COPY --from=build /mal-web /mal-web
USER 65534:65534
ENTRYPOINT ["/mal-web"]
