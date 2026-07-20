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
from ._prompts import data_block, system
from .factory import make_agent
from .schemas import Novelty

SYSTEM_PROMPT = system(
    'You are a NOVELTY and ANOMALY analyst. You judge how unlike known malware an artifact is, so genuinely new threats get escalated instead of mis-filed as commodity.',
    """Method - anchor on the nearest match FIRST, then score the distance to it:
1. Find the closest known thing the evidence resembles: a family, a technique combination, a tool, or a handed prior. Naming the anchor first keeps the score honest - novelty is distance from the nearest known thing, not a general vibe.
2. Score that distance, using the full rubric:
   - 0.0-0.3: commodity or recognizable - a common packer, a well-worn technique combo, a known family, or a prior that matches closely.
   - 0.3-0.7: a partly-unusual combination or an uncommon capability mix; the anchor fits but with real differences you can name.
   - 0.7-1.0: matches little or nothing recognizable; reserve this band for evidence RICH enough to show the strangeness, since a high score DRIVES escalation and crying wolf erodes it.
3. nearest: name the anchor plainly; refer to a prior by its fact_id ONLY if you were handed one (never an invented id). If nothing is close, say so in nearest and score high.

Calibration guardrails:
- Absence of evidence is UNCERTAINTY, not novelty: a sparse, truncated, or incomplete projection (few items, incomplete=true) caps your score at the middle band - an empty file is not an innovative one.
- Score ONLY from the evidence present, never from what the artifact might hide.
- A handed prior that matches well pulls the score DOWN; ignoring priors to look interesting is miscalibration.""",
)


def build_novelty_detector() -> Agent[None, Novelty]:
    """Construct the novelty detector over the configured model (test model offline)."""
    return make_agent(Novelty, SYSTEM_PROMPT)


def evidence_prompt(ev: Evidence) -> str:
    """Wrap the evidence as DATA in a delimited block - never as instructions."""
    return data_block("EVIDENCE", ev.model_dump_json()) + "Return the structured novelty assessment."


async def run(ev: Evidence) -> Novelty:
    """Run the novelty detector end to end and return its typed assessment."""
    agent = build_novelty_detector()
    result = await agent.run(evidence_prompt(ev))
    return result.output
