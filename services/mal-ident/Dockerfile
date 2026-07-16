# mal-ident worker image.
#
# Identification is magika (google's content-type model), which runs on the
# ONNX Runtime. We vendor Microsoft's official self-contained runtime shared
# library, pinned by version (1.24.2, matching what the ort crate targets, so
# the API is exact) and by sha256 per architecture. The rust binary dlopens it
# at run time (see ensure_runtime in main.rs). The magika model itself ships
# embedded in the crate, so the image digest pins model, engine, and code.
#
# The runtime image is scratch. It carries the binary, the vendored runtime,
# and the exact shared-library closure both of them link (glibc, libstdc++,
# libgcc), copied path-for-path so the loader finds everything. No shell, no
# package manager, no coreutils; the no-pivot property holds. Runs as nobody.
#
# Air-gapped builds vendor the same tarball from the offline bundle instead of
# fetching it. The runtime jail (no network, cap-drop ALL, read-only, seccomp)
# is enforced by the spawner; we never TRUST the image for isolation.

FROM rust:1-bookworm AS build

# Optional corporate TLS interception CA for the build stage only; see
# deploy/certs/README.md. Nothing from this survives into the runtime image.
COPY deploy/certs/ /tmp/extra-certs/
RUN cat /tmp/extra-certs/*.pem >> /etc/ssl/certs/ca-certificates.crt 2>/dev/null || true

# Vendor Microsoft's official ONNX Runtime, pinned per arch by sha256.
ARG ORT_VERSION=1.24.2
RUN set -eux; \
    arch="$(uname -m)"; \
    case "$arch" in \
      aarch64) slug="linux-aarch64"; sha="6715b3d19965a2a6981e78ed4ba24f17a8c30d2d26420dbed10aac7ceca0085e" ;; \
      x86_64)  slug="linux-x64";     sha="43725474ba5663642e17684717946693850e2005efbd724ac72da278fead25e6" ;; \
      *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
    esac; \
    url="https://github.com/microsoft/onnxruntime/releases/download/v${ORT_VERSION}/onnxruntime-${slug}-${ORT_VERSION}.tgz"; \
    curl -fsSL "$url" -o /tmp/ort.tgz; \
    echo "${sha}  /tmp/ort.tgz" | sha256sum -c -; \
    mkdir -p /opt/onnxruntime /tmp/ort; \
    tar xzf /tmp/ort.tgz -C /tmp/ort --strip-components=1; \
    cp "/tmp/ort/lib/libonnxruntime.so.${ORT_VERSION}" /opt/onnxruntime/libonnxruntime.so; \
    rm -rf /tmp/ort.tgz /tmp/ort

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY services/mal-ident/ services/mal-ident/
COPY services/mal-extract/ services/mal-extract/
COPY services/mal-static-yara/ services/mal-static-yara/

# sharing=locked: several rust images build concurrently under one `compose
# build` and share these caches; locked serializes access so they cannot race
# unpacking the same crate (the .cargo-ok "File exists" failure).
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build -p mal-ident --release --locked \
    && cp target/release/mal-ident /mal-ident

# Collect the shared-library closure of BOTH the binary and the dlopen'd
# runtime (the runtime's libstdc++/glibc deps are invisible to ldd of the
# binary alone), preserving absolute paths for the loader.
RUN mkdir /runtime; \
    for obj in /mal-ident /opt/onnxruntime/libonnxruntime.so; do \
      ldd "$obj" | awk '{for (i = 1; i <= NF; i++) if ($i ~ /^\//) print $i}'; \
    done | sort -u \
    | while read -r so; do mkdir -p "/runtime$(dirname "$so")"; cp "$so" "/runtime$so"; done

FROM scratch
COPY --from=build /runtime/ /
COPY --from=build /opt/onnxruntime/libonnxruntime.so /opt/onnxruntime/libonnxruntime.so
COPY --from=build /mal-ident /mal-ident
USER 65534:65534
ENTRYPOINT ["/mal-ident"]
