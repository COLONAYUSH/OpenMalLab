# The jailed AI-analyst plane: a long-running Pydantic-AI agent service. Unlike the
# one-shot deterministic workers (capa/floss stream stdin->broker->stdout), this is
# a persistent HTTP service the orchestrator calls, so its containment is the
# isolated plane (no egress, no trusted-store creds, read-only rootfs, non-root -
# enforced in compose) plus the Go broker-analogue Validate on everything it
# returns. 2-stage build so the runtime carries only the venv, no build tools.

# ---- builder ----
FROM python:3.12-slim AS build
WORKDIR /src
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
COPY pyproject.toml ./
COPY malagents ./malagents
# pip goes via Artifactory when a credentialed index is mounted as a build secret;
# absent (CI / clean net) it falls back to public PyPI. never an ARG/layer.
RUN --mount=type=secret,id=pip_conf,target=/etc/pip.conf,required=false \
    python -m venv /opt/venv && \
    /opt/venv/bin/pip install .

# ---- runtime ----
FROM python:3.12-slim
# a non-root, home-less service account; the plane is network-isolated in compose.
RUN useradd --system --no-create-home --uid 65533 malagent
COPY --from=build /opt/venv /opt/venv
COPY malagents /opt/malagents/malagents
ENV PATH=/opt/venv/bin:$PATH PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /opt/malagents
USER malagent
EXPOSE 8099
# bound inside the isolated plane network; the compose network policy, not the
# bind address, is the egress control.
CMD ["uvicorn", "malagents.app:app", "--host", "0.0.0.0", "--port", "8099"]
