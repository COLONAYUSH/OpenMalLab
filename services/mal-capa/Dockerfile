# mal-capa worker image.
#
# capa is a large Python application, so unlike the static-scratch workers this
# one carries a Python runtime. It is built in two stages: a builder installs
# capa into a venv and vendors the pinned rule set, and the runtime copies only
# the venv, the rules, and the wrapper. Everything runs from the read-only
# image at run time (no extraction), so the jail keeps its noexec scratch and
# read-only rootfs intact. For Python engines the CONTAINMENT is the jail
# (network none, all caps dropped, read-only, non-root, resource caps), not
# image minimalism; the boundary proof asserts the jail, not the absence of a
# shell here.
#
# capa rules are Apache-2.0, vendored from the mandiant/capa-rules release that
# matches the capa version and pinned by sha256, so the image digest pins code
# AND rules and nothing is fetched at run time. capa uses its bundled vivisect
# backend: no native disassembler, no Ghidra, arch-neutral.
#
# The capa Python package is fetched at build time. On a network that proxies
# PyPI through a private, credentialed index, pass that index as a BuildKit
# secret (never an ARG or a layer): `--secret id=pip_conf,src=~/.pip/pip.conf`.
# On a clean network the secret is absent and pip uses public PyPI.

FROM python:3.12-slim-bookworm AS build

# Optional corporate TLS interception CA for the build stage only.
COPY deploy/certs/ /tmp/extra-certs/
RUN cat /tmp/extra-certs/*.pem >> /etc/ssl/certs/ca-certificates.crt 2>/dev/null || true

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install capa. The pip_conf secret (if provided) supplies a private index URL
# with its credential; it is mounted only for this layer and never persisted.
# required=false so a clean-network build with no secret falls back to PyPI.
ARG CAPA_VERSION=9.4.0
RUN --mount=type=secret,id=pip_conf,target=/etc/pip.conf,required=false \
    PIP_CERT=/etc/ssl/certs/ca-certificates.crt \
    pip install --no-cache-dir "flare-capa==${CAPA_VERSION}"

# Vendor the matching rule set, pinned by sha256. The slim image has no curl,
# so we fetch with Python's urllib (which honors SSL_CERT_FILE, so the optional
# corp CA appended above is trusted). sha256sum and tar are in the base.
ARG CAPA_RULES_SHA=273591b11737181b3bdaac18964f23627cf10c21c2b143fc9be88e4a33217669
RUN set -eux; \
    url="https://github.com/mandiant/capa-rules/archive/refs/tags/v${CAPA_VERSION}.tar.gz"; \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    python -c "import urllib.request,sys; urllib.request.urlretrieve(sys.argv[1], '/tmp/rules.tgz')" "$url"; \
    echo "${CAPA_RULES_SHA}  /tmp/rules.tgz" | sha256sum -c -; \
    mkdir -p /opt/capa/rules; \
    tar xzf /tmp/rules.tgz -C /opt/capa/rules --strip-components=1; \
    rm -f /tmp/rules.tgz; \
    test -n "$(find /opt/capa/rules -name '*.yml' -print -quit)"

FROM python:3.12-slim-bookworm
COPY --from=build /opt/venv /opt/venv
COPY --from=build /opt/capa /opt/capa
COPY services/mal-capa/wrapper.py /wrapper.py
# HOME/TMPDIR point at the jail's writable scratch tmpfs: capa/vivisect writes
# a rule cache and temp under HOME, and the rootfs is read-only in the jail.
# The orchestrator also sets these on the jail spec; baking them keeps direct
# runs working too.
ENV PATH="/opt/venv/bin:$PATH" MAL_CAPA_RULES=/opt/capa/rules MAL_CAPA_BIN=/opt/venv/bin/capa \
    HOME=/scratch TMPDIR=/scratch
# verify the capability-mapping logic at build time (fails the build if broken).
RUN HOME=/tmp /opt/venv/bin/python /wrapper.py --selftest
USER 65534:65534
ENTRYPOINT ["/opt/venv/bin/python", "/wrapper.py"]
