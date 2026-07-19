"""The analyst agent: the P0 end-to-end round-trip.

It reasons over a defanged, structured Evidence projection and returns a TYPED
Proposal. The typed output IS the security primitive the design chose Pydantic-AI
for: the model's answer is coerced to a schema here, then re-validated and gated
on the Go side. Evidence is passed as DATA in a delimited block, never
concatenated into the instruction; the model can only propose.
"""

from __future__ import annotations

from pydantic_ai import Agent

from ..models import Evidence, Proposal
from ._prompts import system
from .factory import make_agent
from ..tracing import trace

SYSTEM_PROMPT = system(
    'You are a SENIOR MALWARE ANALYST producing the end-to-end assessment. You summarize behavior, propose capability and family hypotheses, and surface indicators - all as reviewable proposals.',
    """Method: reason over the whole evidence projection and produce ONE coherent Proposal.
- summary: a tight analyst-facing paragraph of what the artifact appears to do, consistent with the deterministic verdict.
- hypotheses: capability or family proposals, each with an honest confidence (per the calibration rule) and citations to real fact_ids where you have them. kind names the class (capability, technique, family, or behavior).
- iocs: indicators actually present in the evidence, typed (url, ip, domain, mutex, registry, file). Fabricate none.
- needs_review: set true whenever the evidence is thin or conflicting, or the stakes are high (family attribution, a novel-looking artifact). When in doubt, ask for review.

You add analyst value on top of a deterministic verdict; you never overrule it and you never mark anything safe.""",
)


def build_analyst() -> Agent[None, Proposal]:
    """Construct the analyst agent over the configured model (test model offline)."""
    return make_agent(Proposal, SYSTEM_PROMPT)


def evidence_prompt(ev: Evidence) -> str:
    """Wrap the evidence as DATA in a delimited block - never as instructions."""
    return "<EVIDENCE>\n" + ev.model_dump_json() + "\n</EVIDENCE>\nReturn the structured proposal."


async def analyze(ev: Evidence) -> Proposal:
    """Run the analyst agent end to end and return its typed proposal."""
    with trace("agent:analyst", submission=ev.submission_id):
        agent = build_analyst()
        result = await agent.run(evidence_prompt(ev))
        return result.output
