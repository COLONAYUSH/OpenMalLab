"""The capability reasoner: capa/ATT&CK evidence -> short behavior narratives.

It reasons over the DEFANGED capability evidence (capa matches, ATT&CK technique
findings) plus any retrieved priors, and returns a TYPED Behaviors object: one
Behavior per capability, each naming an ATT&CK technique id, a one-line why, and
citations to the facts it rests on. Evidence and priors are passed as DATA in
delimited blocks, never concatenated into the instruction; the model can only
propose, may never invent a technique the evidence does not carry, and never
issues a verdict. The typed output is re-validated and gated on the Go side.
"""

from __future__ import annotations

from pydantic_ai import Agent

from ..models import Evidence
from ._prompts import system
from .factory import make_agent
from .schemas import Behaviors, Priors

SYSTEM_PROMPT = system(
    'You are a SENIOR REVERSE ENGINEER specializing in capability analysis. You translate low-level capability evidence into precise, ATT&CK-grounded behavior narratives an analyst can act on.',
    """Method: enumerate each DISTINCT capability in the evidence (capa matches, ATT&CK findings). For each, emit ONE Behavior:
- ttp: the ATT&CK technique id it maps to (e.g. 'T1055'), copied VERBATIM from the evidence's attck field. Every behavior MUST set ttp and a one-line why; never leave them blank, and never invent a technique the evidence does not carry.
- why: one line, plain analyst language, grounded in the specific evidence item.
- citations: include one ONLY when a prior gave you a real fact_id for it; otherwise leave it empty. An uncited behavior is a fine low-confidence lead.

Collapse duplicates: the same technique surfaced by several matches becomes ONE behavior citing the strongest evidence. You narrate what the artifact CAN do from the evidence; you never rule on what it IS.""",
)


def build_capability_reasoner() -> Agent[None, Behaviors]:
    """Construct the capability reasoner over the configured model (test model offline)."""
    return make_agent(Behaviors, SYSTEM_PROMPT)


def evidence_prompt(ev: Evidence, priors: Priors | None = None) -> str:
    """Wrap the evidence and any priors as DATA in delimited blocks - never as instructions."""
    prompt = "<EVIDENCE>\n" + ev.model_dump_json() + "\n</EVIDENCE>\n"
    if priors is not None:
        prompt += "<PRIORS>\n" + priors.model_dump_json() + "\n</PRIORS>\n"
    return prompt + "Return the structured behaviors."


async def run(ev: Evidence, priors: Priors | None = None) -> Behaviors:
    """Run the capability reasoner end to end and return its typed behaviors."""
    agent = build_capability_reasoner()
    result = await agent.run(evidence_prompt(ev, priors))
    return result.output
