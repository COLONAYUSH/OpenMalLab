"""Observability must never break analysis: tracing is a no-op without config, and
even when 'enabled' it swallows a missing/unreachable Langfuse rather than raising
into the agent path."""

from malagents.tracing import enabled, trace


def test_tracing_noop_without_config(monkeypatch):
    monkeypatch.delenv("MAL_LANGFUSE_URL", raising=False)
    monkeypatch.delenv("MAL_LANGFUSE_PUBLIC_KEY", raising=False)
    assert enabled() is False
    with trace("agent:test", submission="s"):
        pass  # must not raise


def test_tracing_enabled_but_langfuse_absent_is_safe(monkeypatch):
    # configured, but the langfuse package/host is unavailable: trace() must still
    # be a no-op, never raising into the analysis path.
    monkeypatch.setenv("MAL_LANGFUSE_URL", "http://127.0.0.1:3000")
    monkeypatch.setenv("MAL_LANGFUSE_PUBLIC_KEY", "pk-test")
    assert enabled() is True
    with trace("agent:test", submission="s"):
        pass  # must not raise even if langfuse import/connect fails
