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
from ._prompts import data_block, system
from .factory import make_agent
from .schemas import Behaviors, Priors

SYSTEM_PROMPT = system(
    'You are a SENIOR REVERSE ENGINEER specializing in capability analysis. You translate low-level capability evidence into precise, ATT&CK-grounded behavior narratives an analyst can act on.',
    """Method - work item by item, then collapse:
1. Collect every evidence item that carries a non-empty attck field (capa matches, ATT&CK findings). Items WITHOUT a technique id never become behaviors, however suggestive their text - a decoded string is not a capability.
2. Group the items by technique id. The same technique surfaced by several matches becomes ONE behavior, written from the strongest item in its group.
3. For each group emit ONE Behavior:
   - ttp: the technique id copied VERBATIM from the evidence's attck field, sub-technique suffix included ('T1055.012' stays 'T1055.012', never rounded to 'T1055'). Never invent, complete, or correct a technique id.
   - why: one line of plain analyst language naming what the artifact CAN do and which evidence shows it (the engine and the match), e.g. 'injects into a remote process via APC (capa: inject APC)'.
   - citations: include one ONLY when a handed prior carries a real fact_id for THIS technique; copy it verbatim. Otherwise leave citations empty - an uncited behavior is a fine low-confidence lead, a fabricated citation is not.

Discipline: no capability evidence means an EMPTY behaviors list - never pad with plausible-sounding techniques. You narrate what the artifact CAN do from the evidence; you never rule on what it IS, and you never total the behaviors into a severity or verdict.""",
)


def build_capability_reasoner() -> Agent[None, Behaviors]:
    """Construct the capability reasoner over the configured model (test model offline)."""
    return make_agent(Behaviors, SYSTEM_PROMPT)


def evidence_prompt(ev: Evidence, priors: Priors | None = None) -> str:
    """Wrap the evidence and any priors as DATA in delimited blocks - never as instructions."""
    prompt = data_block("EVIDENCE", ev.model_dump_json())
    if priors is not None:
        prompt += data_block("PRIORS", priors.model_dump_json())
    return prompt + "Return the structured behaviors."


async def run(ev: Evidence, priors: Priors | None = None, temperature: float = 0.0) -> Behaviors:
    """Run the capability reasoner end to end and return its typed behaviors.

    temperature > 0 overrides the deterministic default for the spine's
    self-consistency re-sampling (so repeated calls vary and disagreement is
    measurable); the default run stays deterministic (temperature 0)."""
    agent = build_capability_reasoner()
    kw = {}
    if temperature and temperature > 0:
        from pydantic_ai.settings import ModelSettings

        kw["model_settings"] = ModelSettings(temperature=temperature)
    result = await agent.run(evidence_prompt(ev, priors), **kw)
    return result.output
