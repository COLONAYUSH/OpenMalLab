"""The report_writer agent: the analyst-facing narrative.

It turns the CONFIRMED items - the hypotheses and indicators that survived the
adversarial verifier - into a concise Markdown narrative for a human analyst. It
summarizes and contextualizes; it never issues a verdict the deterministic
pipeline did not reach. Evidence and the confirmed list are passed as DATA in
delimited blocks, never concatenated into the instruction, so hostile strings
carried in the sample cannot steer the writer.
"""

from __future__ import annotations

import json

from pydantic_ai import Agent

from ..models import Evidence
from ._prompts import system
from .factory import make_agent
from .schemas import Report

SYSTEM_PROMPT = system(
    'You are a MALWARE ANALYST writing the incident report. You produce clear, precise, decision-useful narrative from confirmed findings only.',
    """Method: turn the CONFIRMED items - the hypotheses and indicators that survived adversarial verification - into a concise Markdown narrative for a human analyst.

- Write from the CONFIRMED list and the ground-truth evidence ONLY. Introduce no family, capability, or indicator that is not among them.
- Structure for fast reading: a one-line summary, then the confirmed behaviors and indicators with their ATT&CK ids, then their significance. Professional incident-report tone; no speculation, no hedging filler.
- Summarize and contextualize the deterministic verdict; never assert a verdict the pipeline did not reach.
- citations: cite a fact only by a real fact_id a prior gave you; if you have none, return an empty list. Never invent a fact_id or put evidence fields inside a citation object.
- md: the Markdown body, a draft for a human, not a ruling.""",
)


def build_report_writer() -> Agent[None, Report]:
    """Construct the report writer over the configured model (test model offline)."""
    return make_agent(Report, SYSTEM_PROMPT)


def report_prompt(ev: Evidence, confirmed: list[str] | None = None) -> str:
    """Wrap the evidence and the confirmed items as DATA in delimited blocks.

    Both blocks are data to describe, never instructions; hostile text lives
    strictly inside the delimiters and is never concatenated into the command.
    """
    return (
        "<EVIDENCE>\n" + ev.model_dump_json() + "\n</EVIDENCE>\n"
        "<CONFIRMED>\n" + json.dumps(confirmed or []) + "\n</CONFIRMED>\n"
        "Draft the analyst-facing Markdown report from the confirmed items only. "
        "Return the structured report."
    )


async def run(ev: Evidence, confirmed: list[str] | None = None) -> Report:
    """Run the report writer end to end and return its typed report."""
    agent = build_report_writer()
    result = await agent.run(report_prompt(ev, confirmed))
    return result.output
