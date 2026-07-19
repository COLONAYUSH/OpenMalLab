"""The escalation agent: package a stuck decision for a human.

When the deterministic confidence gate cannot dispose of a submission on its own,
it escalates. This agent turns that dead end into a HITL prompt: given the
defanged Evidence and the reason the gate escalated, it returns a TYPED Escalation
- one crisp question and 2 to 4 concrete options an analyst can choose between.
The typed output IS the security primitive: the model's answer is coerced to a
schema here, then re-validated on the Go side. Evidence and the reason are passed
as DATA in delimited blocks, never concatenated into the instruction; the agent
frames the choice, it never makes it.
"""

from __future__ import annotations

from pydantic_ai import Agent

from ..models import Evidence
from ._prompts import system
from .factory import make_agent
from .schemas import Escalation

SYSTEM_PROMPT = system(
    'You are a SOC ESCALATION analyst. You turn a gate dead-end into a crisp decision a human reviewer can make in seconds.',
    """The deterministic gate could not dispose of this submission and escalated it. You are given the evidence and the reason it escalated.

Method: FRAME the decision, do not make it.
- question: one specific, answerable question capturing exactly what the human must decide - not 'is this bad?' but the concrete fork the evidence poses.
- options: 2 to 4 concrete, actionable, mutually-distinct choices (e.g. 'Confirm as the proposed family and block the C2', 'Send for dynamic analysis', 'Assign for deeper manual RE'). Offer a benign option only if the evidence genuinely leaves it open, and only as a choice for the human - you cannot recommend it.

Ground the question and every option in the evidence and the escalation reason; cite fact_ids where they apply.""",
)


def build_escalation() -> Agent[None, Escalation]:
    """Construct the escalation agent over the configured model (test model offline)."""
    return make_agent(Escalation, SYSTEM_PROMPT)


def escalation_prompt(ev: Evidence, reason: str) -> str:
    """Wrap the evidence and the escalation reason as DATA in delimited blocks - never
    as instructions, so hostile text can only be analyzed, never obeyed."""
    return (
        "<EVIDENCE>\n" + ev.model_dump_json() + "\n</EVIDENCE>\n"
        "<ESCALATION_REASON>\n" + reason + "\n</ESCALATION_REASON>\n"
        "Return the packaged decision: one crisp question and 2 to 4 concrete options."
    )


async def run(ev: Evidence, reason: str) -> Escalation:
    """Run the escalation agent end to end and return its typed HITL prompt."""
    agent = build_escalation()
    result = await agent.run(escalation_prompt(ev, reason))
    return result.output
