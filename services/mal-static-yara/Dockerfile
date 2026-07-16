# mal-static-yara worker image.
#
# The binary is fully static (musl, crt-static) and the final image is scratch:
# no shell, no package manager, no libc, no coreutils. If the yara engine is
# ever compromised by a hostile sample, there is nothing in the image to pivot
# to. Rules are baked in at compile time (include_str!) so the image digest
# pins the exact rule set. Runs as nobody (65534).
#
# The runtime jail (no network, cap-drop ALL, read-only rootfs, seccomp,
# resource caps) is enforced by the spawner at `docker run` time. The image is
# hardened too, but we never TRUST the image for isolation.
#
# Tags float for local dev. Air-gapped and production builds pin exact digests
# and pull through the local registry mirror.

FROM rust:1-alpine AS build

# Corporate networks that intercept TLS (Zscaler and friends) break in-container
# fetches from crates.io and apk. Drop the interception root CA into
# deploy/certs/*.pem (gitignored, never committed) and the build stage trusts
# it. On clean networks the glob matches nothing and this is a no-op. The
# runtime image below is scratch: no CA bundle, no network, nothing of this
# survives into the artifact.
COPY deploy/certs/ /tmp/extra-certs/
RUN cat /tmp/extra-certs/*.pem >> /etc/ssl/certs/ca-certificates.crt 2>/dev/null || true

RUN apk add --no-cache musl-dev build-base
WORKDIR /src

# The whole rust workspace is needed for cargo to resolve members.
COPY Cargo.toml Cargo.lock ./
COPY services/mal-ident/ services/mal-ident/
COPY services/mal-extract/ services/mal-extract/
COPY services/mal-static-yara/ services/mal-static-yara/

# Fully static so scratch works. The explicit --target (same triple as the
# host) matters: it keeps RUSTFLAGS off proc-macro and build-script units,
# which cannot be built crt-static. Arch-neutral so the same file builds on
# arm64 and amd64. Cache mounts keep rebuilds fast; the binary must be copied
# out of the cached target dir in the same RUN.
ENV RUSTFLAGS="-C target-feature=+crt-static"
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    TARGET="$(rustc -vV | sed -n 's/host: //p')" \
    && cargo build -p mal-static-yara --release --locked --target "$TARGET" \
    && cp "target/$TARGET/release/mal-static-yara" /mal-static-yara

FROM scratch
COPY --from=build /mal-static-yara /mal-static-yara
USER 65534:65534
ENTRYPOINT ["/mal-static-yara"]
