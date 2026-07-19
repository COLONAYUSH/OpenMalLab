"""The provider's sovereign-safe posture: loopback by default, cloud only on an
explicit opt-in. Mirrors the Go NewLocalProvider loopback enforcement."""

import pytest

from malagents import provider


def test_no_url_returns_test_model(monkeypatch):
    monkeypatch.delenv("MAL_MODEL_URL", raising=False)
    from pydantic_ai.models.test import TestModel

    assert isinstance(provider.get_model(), TestModel)


def test_loopback_and_host_helpers():
    assert provider._is_loopback("127.0.0.1")
    assert provider._is_loopback("localhost")
    assert provider._is_loopback("::1")
    assert not provider._is_loopback("ollama.com")
    assert not provider._is_loopback("8.8.8.8")
    assert not provider._is_loopback("")  # not a host
    assert provider._host_of("https://ollama.com/v1") == "ollama.com"
    assert provider._host_of("127.0.0.1:8000") == "127.0.0.1"  # bare host:port tolerated


def test_loopback_url_builds_without_optin(monkeypatch):
    # the sovereign path: a local model server needs no opt-in and must not raise.
    monkeypatch.setenv("MAL_MODEL_URL", "http://127.0.0.1:8000")
    monkeypatch.delenv("MAL_ALLOW_CLOUD", raising=False)
    from pydantic_ai.models.test import TestModel

    m = provider.get_model()
    assert not isinstance(m, TestModel)


def test_cloud_url_refused_without_optin(monkeypatch):
    # a non-loopback endpoint means egress; without the explicit opt-in it is refused.
    monkeypatch.setenv("MAL_MODEL_URL", "https://ollama.com")
    monkeypatch.delenv("MAL_ALLOW_CLOUD", raising=False)
    with pytest.raises(RuntimeError, match="MAL_ALLOW_CLOUD"):
        provider.get_model()


def test_cloud_url_allowed_with_explicit_optin(monkeypatch):
    monkeypatch.setattr(provider, "_use_system_trust_store", lambda: None)  # no global ssl mutation in a unit test
    monkeypatch.setenv("MAL_MODEL_URL", "https://ollama.com")
    monkeypatch.setenv("MAL_MODEL_KEY", "sk-test")
    monkeypatch.setenv("MAL_ALLOW_CLOUD", "1")
    from pydantic_ai.models.test import TestModel

    m = provider.get_model()  # explicit, audited opt-in -> allowed
    assert not isinstance(m, TestModel)


def test_cloud_enabled_reflects_env(monkeypatch):
    monkeypatch.delenv("MAL_ALLOW_CLOUD", raising=False)
    assert not provider.cloud_enabled()
    for truthy in ("1", "true", "YES", "on"):
        monkeypatch.setenv("MAL_ALLOW_CLOUD", truthy)
        assert provider.cloud_enabled()
    monkeypatch.setenv("MAL_ALLOW_CLOUD", "0")
    assert not provider.cloud_enabled()
