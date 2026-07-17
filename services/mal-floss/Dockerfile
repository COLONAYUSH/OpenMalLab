# mal-floss worker image.
#
# FLOSS is a Python application (like capa). One of its dependencies,
# binary2strings, is a C++ extension with no prebuilt wheel for every arch, so
# the builder needs a compiler; the runtime does not, and stays slim. Runs
# everything from the read-only image, so the jail keeps its noexec scratch and
# read-only rootfs. As with capa, the containment for this Python engine is the
# jail (network none, caps dropped, read-only, non-root, resource caps), not
# image minimalism.
#
# The FLOSS package is fetched at build time. Behind a private, credentialed
# index, pass it as a BuildKit secret (never an ARG or a layer); on a clean
# network it uses public PyPI. See deploy/certs/README.md and the capa image.

FROM python:3.12-slim-bookworm AS build

# Optional corporate TLS interception CA for the build stage only.
COPY deploy/certs/ /tmp/extra-certs/
RUN cat /tmp/extra-certs/*.pem >> /etc/ssl/certs/ca-certificates.crt 2>/dev/null || true

# binary2strings (a FLOSS dep) is a C++ extension; the builder needs a compiler.
RUN apt-get update && apt-get install -y --no-install-recommends g++ python3-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

ARG FLOSS_VERSION=3.1.1
RUN --mount=type=secret,id=pip_conf,target=/etc/pip.conf,required=false \
    PIP_CERT=/etc/ssl/certs/ca-certificates.crt \
    pip install --no-cache-dir "flare-floss==${FLOSS_VERSION}"

FROM python:3.12-slim-bookworm
COPY --from=build /opt/venv /opt/venv
COPY services/mal-floss/wrapper.py /wrapper.py
# HOME/TMPDIR point at the jail's writable scratch: vivisect writes a workspace
# cache under HOME and the rootfs is read-only in the jail. The orchestrator
# also sets these on the jail spec; baking them keeps direct runs working.
ENV PATH="/opt/venv/bin:$PATH" MAL_FLOSS_BIN=/opt/venv/bin/floss HOME=/scratch TMPDIR=/scratch
# verify the string-mapping logic at build time (fails the build if broken).
RUN HOME=/tmp /opt/venv/bin/python /wrapper.py --selftest
USER 65534:65534
ENTRYPOINT ["/opt/venv/bin/python", "/wrapper.py"]
