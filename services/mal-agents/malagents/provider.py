"""Model provider for the agent roster.

One switch with a sovereign-safe default:

- no ``MAL_MODEL_URL`` -> a deterministic in-process ``TestModel`` (no network), so
  the whole service runs and is testable fully offline (the air-gapped default).
- ``MAL_MODEL_URL`` at a LOOPBACK host -> an OpenAI-compatible client to a local
  vLLM/Ollama server. This is the sovereign path: nothing leaves the box.
- ``MAL_MODEL_URL`` at a NON-loopback host -> refused UNLESS ``MAL_ALLOW_CLOUD`` is
  explicitly set. A remote model means evidence egresses the box, so it must be an
  audited, deliberate opt-in - never something a stray env var enables silently.

This mirrors the Go provider's posture: ``NewLocalProvider`` enforces loopback, and
egress stays off unless a deployment explicitly opts in. When the cloud path IS
opted into, evidence is minimized before it leaves (see ``egress.minimize_for_egress``,
applied at the HTTP boundary) so only the analytical signal crosses the wire.
"""

from __future__ import annotations

import ipaddress
import os
from urllib.parse import urlparse


def model_configured() -> bool:
    """True if a live model endpoint is configured (else the test model is used)."""
    return bool(os.environ.get("MAL_MODEL_URL", "").strip())


def _truthy(v: str) -> bool:
    return v.strip().lower() in ("1", "true", "yes", "on")


def cloud_enabled() -> bool:
    """True only when the operator has explicitly opted into remote (cloud) egress."""
    return _truthy(os.environ.get("MAL_ALLOW_CLOUD", ""))


_trust_injected = False


def _use_system_trust_store() -> None:
    """Route TLS verification through the OS trust store for the cloud path.

    Corporate networks commonly terminate TLS with a private root CA that lives in
    the operating-system trust store, not in the certifi bundle the openai/httpx
    client uses by default - so an opt-in cloud endpoint fails to verify. truststore
    (already a transitive dependency) redirects verification to the system store.
    Best-effort and idempotent; a no-op for the loopback path.
    """
    global _trust_injected
    if _trust_injected:
        return
    try:
        import truststore

        truststore.inject_into_ssl()
    except Exception:
        pass  # fall back to certifi - not fatal, just less proxy-tolerant
    _trust_injected = True


def _host_of(url: str) -> str:
    # tolerate a bare host:port (no scheme) the way a careless operator might set it.
    parsed = urlparse(url if "://" in url else "http://" + url)
    return parsed.hostname or ""


def _is_loopback(host: str) -> bool:
    if host == "" or host.lower() == "localhost":
        return host != ""  # "" is not a host; "localhost" is loopback
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False  # a non-numeric, non-localhost name is treated as remote


def get_model():
    """Return a pydantic-ai model, enforcing the loopback-by-default posture.

    Raises RuntimeError if ``MAL_MODEL_URL`` points at a non-loopback host without
    an explicit ``MAL_ALLOW_CLOUD`` opt-in - the air-gapped promise must not be
    broken by a misconfiguration.
    """
    url = os.environ.get("MAL_MODEL_URL", "").strip()
    if not url:
        from pydantic_ai.models.test import TestModel

        return TestModel()

    host = _host_of(url)
    is_cloud = not _is_loopback(host)
    if is_cloud and not cloud_enabled():
        raise RuntimeError(
            "MAL_MODEL_URL points at a non-loopback host (%r) but MAL_ALLOW_CLOUD is "
            "not set. The sovereign default is air-gapped: a remote model endpoint "
            "lets evidence leave the box, so it must be an explicit, audited opt-in. "
            "Set MAL_ALLOW_CLOUD=1 to acknowledge egress, or point MAL_MODEL_URL at a "
            "local (loopback) model server." % host
        )
    if is_cloud:
        _use_system_trust_store()  # tolerate corporate CA on the opt-in cloud path

    # pydantic-ai renamed OpenAIModel -> OpenAIChatModel in its 2.x line. tolerate
    # both so the provider works across the pinned range (and fails loudly, not
    # silently, if the class is gone entirely) - the cloud path is only ever
    # exercised here, so it must not depend on one exact class name.
    try:
        from pydantic_ai.models.openai import OpenAIChatModel as _ChatModel
    except ImportError:  # older pydantic-ai
        from pydantic_ai.models.openai import OpenAIModel as _ChatModel
    from pydantic_ai.providers.openai import OpenAIProvider

    name = os.environ.get("MAL_MODEL_NAME", "local")
    base = url.rstrip("/")
    if not base.endswith("/v1"):
        base += "/v1"
    return _ChatModel(
        name,
        provider=OpenAIProvider(base_url=base, api_key=os.environ.get("MAL_MODEL_KEY", "sk-local")),
    )
