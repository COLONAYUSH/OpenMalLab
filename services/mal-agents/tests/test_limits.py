"""The HTTP surface rejects an oversized request body before it can pin memory."""

from fastapi.testclient import TestClient

from malagents.app import MAX_REQUEST_BYTES, app

client = TestClient(app)


def test_oversized_body_rejected_with_413():
    big = b"x" * (MAX_REQUEST_BYTES + 16)
    r = client.post("/v1/analyze", content=big, headers={"content-type": "application/json"})
    assert r.status_code == 413, r.status_code


def test_normal_sized_request_still_flows():
    # a well-formed, small Evidence body is not blocked by the size guard (it fails
    # later only if the model path errors; here the offline TestModel handles it).
    ev = {"submission_id": "s", "verdict": "SUSPICIOUS", "score": 10, "items": []}
    r = client.post("/v1/analyze", json=ev)
    assert r.status_code == 200, (r.status_code, r.text[:200])
