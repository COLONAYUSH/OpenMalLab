"""The novelty detector agent: how unlike anything known this artifact looks.

It reasons over a defanged, structured Evidence projection and returns a TYPED
Novelty: a score in 0..1 (higher = more novel, which drives escalation) plus the
nearest known thing the artifact resembles. Like every roster agent it can only
propose - the typed output is re-validated and gated on the Go side, and the
deterministic lattice remains the one that disposes. Evidence is passed as DATA in
a delimited block, never concatenated into the instruction.
"""

from __future__ import annotations

from pydantic_ai import Agent

from ..models import Evidence
from ._prompts import system
from .factory import make_agent
from .schemas import Novelty

SYSTEM_PROMPT = system(
    'You are a NOVELTY and ANOMALY analyst. You judge how unlike known malware an artifact is, so genuinely new threats get escalated instead of mis-filed as commodity.',
    """Method: compare the evidence against the space of known techniques, families, and tooling, and emit a calibrated score with the nearest match.

- score (0.0 to 1.0): 0.0-0.3 = commodity or recognizable (a common packer, a well-worn technique combo, a known family); 0.3-0.7 = a partly-unusual combination or an uncommon capability mix; 0.7-1.0 = matches little or nothing recognizable. A higher score DRIVES escalation, so do not inflate it - reserve high scores for the genuinely unfamiliar.
- nearest: name the closest known thing (a family, technique, tool, or prior); refer to a prior's fact_id if you were given one. If nothing is close, say so and score high.

Base the score ONLY on the evidence present. Absence of evidence is uncertainty, not novelty: a sparse or truncated projection is not an innovative artifact.""",
)


def build_novelty_detector() -> Agent[None, Novelty]:
    """Construct the novelty detector over the configured model (test model offline)."""
    return make_agent(Novelty, SYSTEM_PROMPT)


def evidence_prompt(ev: Evidence) -> str:
    """Wrap the evidence as DATA in a delimited block - never as instructions."""
    return "<EVIDENCE>\n" + ev.model_dump_json() + "\n</EVIDENCE>\nReturn the structured novelty assessment."


async def run(ev: Evidence) -> Novelty:
    """Run the novelty detector end to end and return its typed assessment."""
    agent = build_novelty_detector()
    result = await agent.run(evidence_prompt(ev))
    return result.output
