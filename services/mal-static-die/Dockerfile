# mal-static-die worker image: Detect It Easy (the headless "diec" console),
# jailed like every other engine. diec fingerprints packers, protectors,
# compilers, linkers and crypto on PE/ELF/Mach-O and prints json we map to the
# engine contract. For a Python-thin engine the CONTAINMENT is the jail (network
# none, all caps dropped, read-only rootfs, non-root, resource caps), not image
# minimalism; the boundary proof asserts the jail, not the absence of a shell.
#
# CLEAN-NETWORK BUILD NOTE (read before building): DIE is fetched from its GitHub
# release at build time, so this image builds on a machine with network egress
# (GitHub's CI runners, or a clean laptop), NOT inside a corporate proxy that
# firewalls the build sandbox. Pin the release you want by filling DIE_DEB_URL
# and DIE_SHA256 below from github.com/horsicq/DIE-engine/releases (pick the
# Debian amd64 .deb that matches this base). The sha256 pin is mandatory: an
# air-gapped platform does not run an unverified download. See docs/DIE-HANDOFF.md.
#
# This image is intentionally NOT in the default `build` compose profile, so the
# standard `docker compose --profile build build` (and CI) never attempts this
# networked build until the release above is pinned and verified. Build it with
# `docker compose --profile build-die build` once the pins are filled.

FROM debian:12

# Optional corporate TLS interception CA for the build stage only. Build context
# is the repo root, so this path is repo-relative.
COPY deploy/certs/ /tmp/extra-certs/
RUN cat /tmp/extra-certs/*.pem >> /etc/ssl/certs/ca-certificates.crt 2>/dev/null || true

# Detect It Easy, pinned by sha256. Fill these two for your target release; the
# .deb pulls the Qt runtime diec links against. Retry loops survive a throttling
# mirror (same pattern as mal-detonate).
ARG DIE_DEB_URL=https://github.com/horsicq/DIE-engine/releases/download/3.10/die_3.10_Debian_12_amd64.deb
ARG DIE_SHA256=REPLACE_WITH_THE_RELEASE_SHA256
RUN set -eux; \
    for i in 1 2 3 4 5; do apt-get update && break || sleep 5; done; \
    for i in 1 2 3 4 5; do apt-get install -y --no-install-recommends ca-certificates curl python3 && break || sleep 5; done; \
    curl -fsSL "$DIE_DEB_URL" -o /tmp/die.deb; \
    echo "${DIE_SHA256}  /tmp/die.deb" | sha256sum -c -; \
    for i in 1 2 3 4 5; do apt-get install -y --no-install-recommends /tmp/die.deb && break || sleep 5; done; \
    rm -f /tmp/die.deb; \
    rm -rf /var/lib/apt/lists/*; \
    command -v diec

COPY services/mal-static-die/wrapper.py /wrapper.py
# diec resolves on PATH (the .deb installs it under /usr/bin). HOME/TMPDIR point
# at the jail's writable scratch: diec writes its signature-db cache under HOME,
# and the rootfs is read-only in the jail. The orchestrator also sets these on
# the jail spec; baking them keeps direct runs working too.
ENV MAL_DIE_BIN=diec HOME=/scratch TMPDIR=/scratch
# verify the detection-mapping logic at build time (fails the build if broken).
# pure logic, so it runs without a sample and without invoking diec.
RUN HOME=/tmp python3 /wrapper.py --selftest
USER 65534:65534
ENTRYPOINT ["python3", "/wrapper.py"]
