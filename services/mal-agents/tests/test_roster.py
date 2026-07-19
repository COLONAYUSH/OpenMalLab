"""The roster dispatcher, fully offline (TestModel). Every named agent must run
and return a value through the shared call, and an unknown name must fail closed."""

import pytest

from malagents.agents.roster import ROSTER, run_agent
from malagents.models import Evidence, EvidenceItem


async def test_every_roster_agent_runs_offline(monkeypatch):
    monkeypatch.delenv("MAL_MODEL_URL", raising=False)  # deterministic TestModel
    ev = Evidence(
        submission_id="s",
        verdict="UNKNOWN",
        items=[EvidenceItem(engine="mal-capa", type="capability", detail="inject", attck="T1055")],
    )
    for name in ROSTER:
        out = await run_agent(name, ev, priors=None, claim="emotet-like", reason="novel", confirmed=["x"])
        assert out is not None, f"{name} returned nothing"


async def test_unknown_agent_fails_closed():
    with pytest.raises(ValueError):
        await run_agent("does-not-exist", Evidence())
