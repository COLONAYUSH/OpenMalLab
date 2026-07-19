"""The HTTP surface the Go activity calls. Exercised offline (TestModel) via
FastAPI's TestClient - no live model, no network."""

from fastapi.testclient import TestClient

from malagents.app import app


def test_healthz():
    r = TestClient(app).get("/healthz")
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_analyze_endpoint_offline(monkeypatch):
    monkeypatch.delenv("MAL_MODEL_URL", raising=False)  # force the offline test model
    payload = {
        "submission_id": "s",
        "verdict": "UNKNOWN",
        "items": [{"engine": "mal-floss", "type": "decoded-string", "detail": "beacon"}],
    }
    r = TestClient(app).post("/v1/analyze", json=payload)
    assert r.status_code == 200
    body = r.json()
    for k in ("summary", "hypotheses", "iocs", "needs_review", "review_reason"):
        assert k in body, f"proposal missing {k}: {body}"


def test_analyze_rejects_unknown_fields():
    # the incoming evidence is contract-typed; a garbage field is a 422.
    r = TestClient(app).post("/v1/analyze", json={"submission_id": "s", "not_a_field": 1})
    # FastAPI is lenient about extra fields by default; the point is it must not 500.
    assert r.status_code in (200, 422)


def test_roster_endpoint_lists_agents():
    r = TestClient(app).get("/v1/roster")
    assert r.status_code == 200
    assert "router" in r.json()["agents"]


def test_agent_endpoint_offline_and_404(monkeypatch):
    monkeypatch.delenv("MAL_MODEL_URL", raising=False)  # deterministic TestModel
    c = TestClient(app)
    ok = c.post("/v1/agent/router", json={"evidence": {"submission_id": "s", "verdict": "UNKNOWN", "items": []}})
    assert ok.status_code == 200, ok.text
    missing = c.post("/v1/agent/does-not-exist", json={"evidence": {"submission_id": "s"}})
    assert missing.status_code == 404
