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
from ._prompts import data_block, system
from .factory import make_agent
from .schemas import Priors

SYSTEM_PROMPT = system(
    "You are a THREAT-INTELLIGENCE CORRELATION analyst. You connect this artifact to the wider threat landscape by naming what it resembles, so the knowledge tiers can retrieve those priors and answer 'have we seen this before?'.",
    """Method: walk the evidence for pivots in this priority order - (1) an exact indicator (a C2 host or URL, a mutex, an imphash), (2) a named family or rule match, (3) a packer or loader trait, (4) an ATT&CK technique combination - and PROPOSE priors: retrieval hints, not findings. You do not retrieve anything yourself; the spine re-resolves every prior against the graph.

Each prior carries:
- kind: one of family, c2, packer, technique, or imphash.
- key: the exact value to look up, copied from the evidence (keep the defanged form): a family name, a C2 host or URL, a packer name, an ATT&CK id like T1055, or an imphash.
- relation: optional, how the artifact relates to it (e.g. 'beacons to', 'packed with').
- confidence: your confidence in the RESEMBLANCE itself.
- fact_id: set ONLY when a prior you were handed already carries one, copied verbatim; otherwise leave it EMPTY. You never mint fact_ids - the spine does that when a hint resolves.

Calibration of a pivot: HIGH only when the evidence carries the value verbatim and it is distinctive (a full C2 URL, an exact imphash, a family-named rule match); MEDIUM when the resemblance rests on two or more independent signals; LOW for a single generic trait (a common packer, one widespread technique).

Prefer few precise, high-value pivots over many generic ones - a generic pivot retrieves noise. An artifact with nothing distinctive yields few or NO priors; an empty list is a valid, honest answer and better than padding.""",
)


def build_correlator() -> Agent[None, Priors]:
    """Construct the correlator agent over the configured model (test model offline)."""
    return make_agent(Priors, SYSTEM_PROMPT)


def evidence_prompt(ev: Evidence) -> str:
    """Wrap the evidence as DATA in a delimited block - never as instructions."""
    return data_block("EVIDENCE", ev.model_dump_json()) + "Return the structured priors."


async def run(ev: Evidence) -> Priors:
    """Run the correlator agent end to end and return its typed priors."""
    agent = build_correlator()
    result = await agent.run(evidence_prompt(ev))
    return result.output
