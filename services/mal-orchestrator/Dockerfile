# mal-orchestrator image: the durable brain.
#
# Static go binary on scratch. It runs the temporal worker that owns the
# SubmissionWorkflow and spawns the jailed analysis containers as siblings
# through the engine socket. That socket is the spawn authority in phase 1,
# so this container runs as root against it; everything else about it is
# still locked down in compose (read-only rootfs, cap-drop ALL,
# no-new-privileges). Mediating the socket behind a narrower spawner api is
# later-phase work and tracked in the design docs.
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
COPY services/mal-orchestrator/ services/mal-orchestrator/
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /mal-orchestrator ./services/mal-orchestrator

FROM scratch
COPY --from=build /mal-orchestrator /mal-orchestrator
ENTRYPOINT ["/mal-orchestrator"]
