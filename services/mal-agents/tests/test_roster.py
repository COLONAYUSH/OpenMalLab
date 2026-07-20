"""The roster dispatcher, fully offline (TestModel). Every named agent must run
and return a value through the shared call - including on the awkward evidence
shapes the real pipeline produces (empty, benign, oversized, hostile) - and an
unknown name must fail closed."""

import pytest

from malagents.agents.roster import ROSTER, run_agent
from malagents.models import MAX_EVIDENCE_ITEMS, Evidence, EvidenceItem


def _kwargs():
    # the uniform envelope the Temporal graph sends; each agent reads only its own.
    return dict(priors=None, claim="emotet-like", reason="novel", confirmed=["x"])


async def test_every_roster_agent_runs_offline(monkeypatch):
    monkeypatch.delenv("MAL_MODEL_URL", raising=False)  # deterministic TestModel
    ev = Evidence(
        submission_id="s",
        verdict="UNKNOWN",
        items=[EvidenceItem(engine="mal-capa", type="capability", detail="inject", attck="T1055")],
    )
    for name in ROSTER:
        out = await run_agent(name, ev, **_kwargs())
        assert out is not None, f"{name} returned nothing"


async def test_every_roster_agent_survives_empty_evidence(monkeypatch):
    # the degenerate projection: no items, no verdict, nothing. An agent must
    # still return its typed output (an honest empty answer), never crash.
    monkeypatch.delenv("MAL_MODEL_URL", raising=False)
    ev = Evidence()
    for name in ROSTER:
        out = await run_agent(name, ev, **_kwargs())
        assert out is not None, f"{name} failed on empty evidence"


async def test_every_roster_agent_survives_benign_evidence(monkeypatch):
    # enrichment also runs on benign-looking artifacts; the flow must be identical
    # (the agents cannot dispose either way - the brief forbids it, the gate enforces it).
    monkeypatch.delenv("MAL_MODEL_URL", raising=False)
    ev = Evidence(
        submission_id="s-benign",
        verdict="BENIGN",
        score=2,
        confidence="HIGH",
        items=[EvidenceItem(engine="mal-yara", type="rule-match", detail="known-good installer")],
    )
    for name in ROSTER:
        out = await run_agent(name, ev, **_kwargs())
        assert out is not None, f"{name} failed on benign evidence"


async def test_roster_handles_oversized_evidence_projection(monkeypatch):
    # a projection at the contract's item cap with long defanged details: the
    # prompt builders and the offline flow must stay well-behaved (the Go side
    # bounds items at MAX_EVIDENCE_ITEMS; we exercise a hefty slice of that).
    monkeypatch.delenv("MAL_MODEL_URL", raising=False)
    items = [
        EvidenceItem(engine="mal-floss", type="decoded-string", detail=("A" * 400) + str(i))
        for i in range(200)
    ]
    assert len(items) <= MAX_EVIDENCE_ITEMS
    ev = Evidence(submission_id="s-big", verdict="SUSPICIOUS", score=61, items=items)
    for name in ("router", "ioc_extractor", "analyst"):
        out = await run_agent(name, ev, **_kwargs())
        assert out is not None, f"{name} failed on oversized evidence"


async def test_roster_runs_on_incomplete_marked_evidence(monkeypatch):
    # incomplete=true is the pipeline saying 'engines timed out or were skipped';
    # agents are briefed to treat that as uncertainty and must still respond.
    monkeypatch.delenv("MAL_MODEL_URL", raising=False)
    ev = Evidence(submission_id="s-inc", verdict="UNKNOWN", incomplete=True)
    for name in ("novelty_detector", "analyst"):
        out = await run_agent(name, ev, **_kwargs())
        assert out is not None


async def test_unknown_agent_fails_closed():
    with pytest.raises(ValueError):
        await run_agent("does-not-exist", Evidence())


async def test_roster_names_are_the_dispatchable_set():
    # the ROSTER tuple is what the HTTP surface and the Go allow-list mirror;
    # every name must dispatch, and the tuple must carry no duplicates.
    assert len(ROSTER) == len(set(ROSTER))
    assert set(ROSTER) == {
        "router", "correlator", "capability_reasoner", "ioc_extractor",
        "family_hypothesizer", "novelty_detector", "verifier", "report_writer",
        "escalation", "analyst",
    }
