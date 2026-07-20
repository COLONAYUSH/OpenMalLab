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
from ._prompts import data_block, system
from .factory import make_agent
from ..tracing import trace

SYSTEM_PROMPT = system(
    'You are a SENIOR MALWARE ANALYST producing the end-to-end assessment. You summarize behavior, propose capability and family hypotheses, and surface indicators - all as reviewable proposals.',
    """Method - read everything, then write ONE coherent Proposal:
1. summary: a tight analyst-facing paragraph of what the artifact appears to do, consistent with the deterministic verdict - never restating it as your own finding, never contradicting it.
2. hypotheses: capability or family proposals. kind names the class (capability, technique, family, or behavior); claim is one grounded sentence. Calibrate each INDEPENDENTLY: HIGH only for signature-grade certainty (an exact rule or constant match), MEDIUM for several corroborating signals, LOW for a single weak or circumstantial one - and family claims follow the conservative ladder: a broad class at LOW unless a family-specific signal is present.
3. iocs: indicators actually present in the evidence, typed by their most specific type (url, ip, domain, mutex, registry, file), values copied as they appear (defanged form preserved). Fabricate and complete nothing.
4. needs_review + review_reason: set true whenever the evidence is thin or conflicting, the artifact looks novel, or any hypothesis is high-stakes (family attribution always is); review_reason then says in one line what a human should check. When in doubt, ask for review - a wasted review costs minutes, a missed one costs an incident.

Citation discipline: cite only fact_ids a prior actually handed you, copied verbatim - never invent, guess, or reconstruct one. A claim with no real fact_id carries an EMPTY citations list and rides at LOW confidence as a lead. You add analyst value on top of a deterministic verdict; you never overrule it and you never mark anything safe.""",
)


def build_analyst() -> Agent[None, Proposal]:
    """Construct the analyst agent over the configured model (test model offline)."""
    return make_agent(Proposal, SYSTEM_PROMPT)


def evidence_prompt(ev: Evidence) -> str:
    """Wrap the evidence as DATA in a delimited block - never as instructions."""
    return data_block("EVIDENCE", ev.model_dump_json()) + "Return the structured proposal."


async def analyze(ev: Evidence) -> Proposal:
    """Run the analyst agent end to end and return its typed proposal."""
    with trace("agent:analyst", submission=ev.submission_id):
        agent = build_analyst()
        result = await agent.run(evidence_prompt(ev))
        return result.output
