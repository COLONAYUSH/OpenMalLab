"""The Go<->Python contract must not drift: the JSON field names here are exactly
the ones the Go aiplane types use, or the roster's output would not validate on
the Go side."""

import json

from malagents.models import (
    Citation,
    Evidence,
    EvidenceItem,
    Hypothesis,
    Proposal,
    ProposedIOC,
)


def test_evidence_json_field_names():
    ev = Evidence(
        submission_id="s",
        sha256="abc",
        file_type="pebin",
        verdict="MALICIOUS",
        score=95,
        confidence="HIGH",
        items=[EvidenceItem(engine="mal-yara", type="yara", detail="hit", attck="T1055", verdict="MALICIOUS", confidence="HIGH", path="p")],
    )
    d = json.loads(ev.model_dump_json())
    assert set(d) == {"submission_id", "sha256", "file_type", "verdict", "score", "confidence", "incomplete", "items"}
    assert d["items"][0]["attck"] == "T1055"


def test_proposal_round_trip_field_names():
    p = Proposal(
        summary="a downloader",
        hypotheses=[Hypothesis(kind="technique", claim="proc inj", confidence="LOW", citations=[Citation(fact_id="kf_1", kind="attck", key="T1055")])],
        iocs=[ProposedIOC(type="url", value="http://c2/x")],
        needs_review=True,
        review_reason="novel",
    )
    d = json.loads(p.model_dump_json())
    assert set(d) == {"summary", "hypotheses", "iocs", "needs_review", "review_reason"}
    assert d["hypotheses"][0]["citations"][0]["fact_id"] == "kf_1"
    assert d["needs_review"] is True
    # exact re-parse: the contract is stable through a full round trip.
    assert Proposal.model_validate_json(p.model_dump_json()) == p
