# mal-extract worker image.
#
# Pure-Rust, fully static (musl, crt-static), final image scratch: no shell, no
# libc, nothing to pivot to if a hostile archive ever subverts the parser. It
# reads one archive at /in/sample (read-only) and writes content-addressed
# children into /out (the one writable mount the jail grants an extractor).
#
# The runtime jail (no network, cap-drop ALL, read-only rootfs, seccomp,
# resource caps, and the single writable /out) is enforced by the spawner. The
# image is hardened too, but we never TRUST the image for isolation.
#
# Tags float for local dev. Air-gapped and production builds pin exact digests.

FROM rust:1-alpine AS build

# Optional corporate TLS interception CA for the build stage only; see
# deploy/certs/README.md. The scratch runtime image carries no trust store.
COPY deploy/certs/ /tmp/extra-certs/
RUN cat /tmp/extra-certs/*.pem >> /etc/ssl/certs/ca-certificates.crt 2>/dev/null || true

RUN apk add --no-cache musl-dev build-base
WORKDIR /src

COPY Cargo.toml Cargo.lock ./
COPY services/mal-ident/ services/mal-ident/
COPY services/mal-extract/ services/mal-extract/
COPY services/mal-static-yara/ services/mal-static-yara/

# Static build. Explicit --target (host triple) keeps crt-static off proc-macro
# and build-script units. Arch-neutral so it builds on arm64 and amd64.
ENV RUSTFLAGS="-C target-feature=+crt-static"
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    TARGET="$(rustc -vV | sed -n 's/host: //p')" \
    && cargo build -p mal-extract --release --locked --target "$TARGET" \
    && cp "target/$TARGET/release/mal-extract" /mal-extract

FROM scratch
COPY --from=build /mal-extract /mal-extract
USER 65534:65534
ENTRYPOINT ["/mal-extract"]
