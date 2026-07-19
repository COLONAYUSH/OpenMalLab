"""The correlator agent: propose priors to look up in the knowledge graph.

It reasons over a defanged, structured Evidence projection and returns TYPED
Priors - the families, C2 endpoints, packers, ATT&CK techniques, and imphashes
this artifact resembles - as retrieval HINTS for the knowledge tiers, never as
findings. The typed output is coerced to a schema here, then re-validated and
gated on the Go side. Evidence is passed as DATA in a delimited block, never
concatenated into the instruction; the correlator can only propose what to look
up, and the Temporal spine re-resolves every prior against the graph.
"""

from __future__ import annotations

from pydantic_ai import Agent

from ..models import Evidence
from ._prompts import system
from .factory import make_agent
from .schemas import Priors

SYSTEM_PROMPT = system(
    "You are a THREAT-INTELLIGENCE CORRELATION analyst. You connect this artifact to the wider threat landscape by naming what it resembles, so the knowledge tiers can retrieve those priors and answer 'have we seen this before?'.",
    """Method: pivot on every strong, distinctive signal in the evidence and PROPOSE priors - retrieval hints, not findings - for the spine to look up. You do not retrieve anything yourself.

Each prior carries:
- kind: one of family, c2, packer, technique, or imphash.
- key: the exact value to look up (a family name, a C2 host or URL, a packer name, an ATT&CK id like T1055, or an imphash).
- relation: optional, how the artifact relates to it (e.g. 'beacons to', 'packed with').
- confidence: LOW / MEDIUM / HIGH per the calibration rule.
- fact_id: set ONLY when a prior you were handed already carries one; otherwise leave it empty (these are hints the spine re-resolves).

Prefer precise, high-value pivots (a specific C2 host, a distinctive imphash, a named family) over generic ones. An artifact with nothing distinctive yields few or no priors - that is a valid, honest answer.""",
)


def build_correlator() -> Agent[None, Priors]:
    """Construct the correlator agent over the configured model (test model offline)."""
    return make_agent(Priors, SYSTEM_PROMPT)


def evidence_prompt(ev: Evidence) -> str:
    """Wrap the evidence as DATA in a delimited block - never as instructions."""
    return "<EVIDENCE>\n" + ev.model_dump_json() + "\n</EVIDENCE>\nReturn the structured priors."


async def run(ev: Evidence) -> Priors:
    """Run the correlator agent end to end and return its typed priors."""
    agent = build_correlator()
    result = await agent.run(evidence_prompt(ev))
    return result.output
