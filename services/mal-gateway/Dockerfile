# mal-gateway image: the front door.
#
# Static go binary on scratch, non-root. The gateway never parses hostile
# bytes; it hashes them, stores them in the vault volume, and starts the
# durable workflow. Its rootfs is read-only at runtime; the only writable
# paths are the vault volume and a tmpfs /tmp for multipart spooling.
#
# Tags float for local dev. Air-gapped and production builds pin exact
# digests and pull through the local registry mirror.

FROM golang:1.26-alpine AS build

# Optional corporate TLS interception CA for the build stage only; see
# deploy/certs/README.md. Nothing from this survives into the runtime image.
COPY deploy/certs/ /tmp/extra-certs/
RUN cat /tmp/extra-certs/*.pem >> /etc/ssl/certs/ca-certificates.crt 2>/dev/null || true

WORKDIR /src
COPY go.mod go.sum ./
COPY internal/ internal/
COPY services/mal-gateway/ services/mal-gateway/
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /mal-gateway ./services/mal-gateway

FROM scratch
COPY --from=build /mal-gateway /mal-gateway
USER 65534:65534
ENTRYPOINT ["/mal-gateway"]
