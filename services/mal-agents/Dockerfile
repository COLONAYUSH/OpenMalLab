# The jailed AI-analyst plane: a long-running Pydantic-AI agent service. Unlike the
# one-shot deterministic workers (capa/floss stream stdin->broker->stdout), this is
# a persistent HTTP service the orchestrator calls, so its containment is the
# isolated plane (no egress, no trusted-store creds, read-only rootfs, non-root -
# enforced in compose) plus the Go broker-analogue Validate on everything it
# returns. 2-stage build so the runtime carries only the venv, no build tools.
#
# Build context is the REPO ROOT (compose sets context: ..), so source paths are
# repo-relative (services/mal-agents/...), matching the capa/floss workers. On a
# network that proxies PyPI through a private, credentialed index, pass it as a
# BuildKit secret (never an ARG/layer): --secret id=pip_conf,src=~/.pip/pip.conf.

# ---- builder ----
FROM python:3.12-slim-bookworm AS build
WORKDIR /src
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
# Optional corporate TLS interception CA for the build stage only (pip over a
# proxied/Artifactory index must trust it); absent on a clean network.
COPY deploy/certs/ /tmp/extra-certs/
RUN cat /tmp/extra-certs/*.pem >> /etc/ssl/certs/ca-certificates.crt 2>/dev/null || true
COPY services/mal-agents/pyproject.toml ./
COPY services/mal-agents/malagents ./malagents
# pip goes via Artifactory when the credentialed index is mounted as a secret;
# absent (CI / clean net) it falls back to public PyPI. never an ARG/layer.
RUN --mount=type=secret,id=pip_conf,target=/etc/pip.conf,required=false \
    PIP_CERT=/etc/ssl/certs/ca-certificates.crt \
    python -m venv /opt/venv && \
    /opt/venv/bin/pip install .

# ---- runtime ----
FROM python:3.12-slim-bookworm
# a non-root, home-less service account; the plane is network-isolated in compose.
RUN useradd --system --no-create-home --uid 65533 malagent
COPY --from=build /opt/venv /opt/venv
COPY services/mal-agents/malagents /opt/malagents/malagents
ENV PATH=/opt/venv/bin:$PATH PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /opt/malagents
USER malagent
EXPOSE 8099
# bound inside the isolated plane network; the compose network policy, not the
# bind address, is the egress control.
CMD ["uvicorn", "malagents.app:app", "--host", "0.0.0.0", "--port", "8099"]
