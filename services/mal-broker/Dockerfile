# mal-broker image: the guard on the worker-to-control boundary.
#
# It decodes hostile-derived bytes, so it runs under the same jail as the
# workers: no network, no credentials, no filesystem beyond its own binary.
# Static go binary on scratch, non-root. stdin in, validated stdout out,
# nonzero exit on any violation.
#
# Tags float for local dev. Air-gapped and production builds pin exact digests
# and pull through the local registry mirror.

FROM golang:1.26-alpine AS build

# Optional corporate TLS interception CA for the build stage only; see the
# note in services/mal-static-yara/Dockerfile and deploy/certs/README.md.
COPY deploy/certs/ /tmp/extra-certs/
RUN cat /tmp/extra-certs/*.pem >> /etc/ssl/certs/ca-certificates.crt 2>/dev/null || true

WORKDIR /src
COPY go.mod go.sum ./
COPY internal/ internal/
COPY services/mal-broker/ services/mal-broker/
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /mal-broker ./services/mal-broker

FROM scratch
COPY --from=build /mal-broker /mal-broker
USER 65534:65534
ENTRYPOINT ["/mal-broker"]
