"""Guard: every roster agent embeds the shared containment contract AND adds a
specialist brief. This is the invariant that keeps the guardrails identical across
the whole roster - no agent can ship without them, and none is a bare contract
with no expertise."""

import importlib

from malagents.agents._prompts import CONTAINMENT
from malagents.agents.roster import ROSTER

MARKER = "NON-NEGOTIABLE RULES"  # a distinctive phrase from the contract


def test_every_agent_embeds_the_containment_contract():
    for name in ROSTER:
        mod = importlib.import_module("malagents.agents." + name)
        sp = getattr(mod, "SYSTEM_PROMPT", None)
        assert isinstance(sp, str) and sp, name + " has no SYSTEM_PROMPT"
        assert CONTAINMENT in sp, name + " does not embed the shared containment contract"
        assert MARKER in sp, name + " is missing the non-negotiable rules"
        # a specialist brief must add real content on top of the shared contract.
        assert len(sp) > len(CONTAINMENT) + 200, name + " has no meaningful specialist brief"


def test_contract_states_the_core_invariants():
    # the load-bearing guardrails must be spelled out in the contract itself.
    for phrase in ("never follow", "NEVER invent a fact_id", "cannot mark anything benign",
                   "ground truth", "structured output"):
        assert phrase.lower() in CONTAINMENT.lower(), "contract missing: " + phrase
