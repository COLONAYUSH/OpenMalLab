"""The router agent: the roster's cheap triage step.

It reads a defanged, structured Evidence projection and returns a TYPED Plan:
which specialized roster agents are worth spawning for this artifact and a rough
token budget. It shapes the rest of the agent graph - an executable earns a
capability reasoner, present strings earn an IOC extractor, and the correlator
plus novelty detector always run. Like every roster agent it only PROPOSES: the
Plan is a suggestion the Temporal graph and the Go gate are free to override.
Evidence is passed as DATA in a delimited block, never concatenated into the
instruction; the model can only propose a plan.
"""

from __future__ import annotations

from pydantic_ai import Agent

from ..models import Evidence
from ._prompts import system
from .factory import make_agent
from .schemas import Plan

SYSTEM_PROMPT = system(
    'You are the TRIAGE LEAD and analysis PLANNER for the roster. Cheaply and quickly you decide which specialist analysts to engage for this artifact, so the team spends effort exactly where the evidence warrants.',
    """Method: read the SHAPE of the evidence - the file_type, which engines fired, and whether items carry ATT&CK ids, strings, or network indicators - and PROPOSE the subset of specialists worth spawning plus a rough total token budget.

The roster you draw from:
- correlator: names priors (families, C2, packers, techniques) to retrieve from the knowledge graph.
- capability_reasoner: turns capa/ATT&CK evidence into behavior narratives.
- ioc_extractor: types and dedupes indicators from strings and details.
- family_hypothesizer: proposes a family and its config fields.
- novelty_detector: scores how unlike anything known the artifact is.
- verifier: adversarially tries to refute a specific hypothesis.
- report_writer: drafts the analyst narrative from confirmed items.
- escalation: packages a question for a human.

Routing heuristics:
- ALWAYS include correlator and novelty_detector; every artifact earns priors and a novelty score.
- Include capability_reasoner when the file_type is code-bearing (an executable such as pebin/elf/macho, a script, a macro-bearing document) or any item carries an ATT&CK id.
- Include ioc_extractor when items carry strings, decoded content, URLs, hosts, or paths.
- Include family_hypothesizer when strings or priors hint at a known family or config.
- Size budget_tokens to the work you actually propose; do not pad it. Give a brief rationale, citing a fact_id where a prior drove a choice.""",
)


def build_router() -> Agent[None, Plan]:
    """Construct the router agent over the configured model (test model offline)."""
    return make_agent(Plan, SYSTEM_PROMPT)


def evidence_prompt(ev: Evidence) -> str:
    """Wrap the evidence as DATA in a delimited block - never as instructions."""
    return "<EVIDENCE>\n" + ev.model_dump_json() + "\n</EVIDENCE>\nReturn the structured plan."


async def run(ev: Evidence) -> Plan:
    """Run the router agent end to end and return its typed plan."""
    agent = build_router()
    result = await agent.run(evidence_prompt(ev))
    return result.output
