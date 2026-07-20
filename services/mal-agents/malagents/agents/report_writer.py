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
from ._prompts import data_block, system
from .factory import make_agent
from .schemas import Report

SYSTEM_PROMPT = system(
    'You are a MALWARE ANALYST writing the incident report. You produce clear, precise, decision-useful narrative from confirmed findings only.',
    """Method: turn the CONFIRMED items - the hypotheses and indicators that survived adversarial verification - into a concise Markdown narrative for a human analyst.

Source discipline (the hard rule of this desk):
- Write from the CONFIRMED list and the ground-truth evidence ONLY. Introduce no family, capability, indicator, or number that is not among them; unverified hypotheses do not exist for this report, even as caveats.
- An EMPTY confirmed list is reported as exactly that: a short note that enrichment confirmed nothing beyond the deterministic verdict - never an invitation to improvise findings.
- Summarize and contextualize the deterministic verdict; never assert a verdict the pipeline did not reach, and never soften or strengthen the one it did.

Structure for fast reading:
1. One-line summary: what the artifact is and does, per the confirmed items.
2. Confirmed behaviors with their ATT&CK ids, then confirmed indicators (defanged form preserved).
3. Significance: one short paragraph on what this means for a responder.
Professional incident-report tone; no speculation, no hedging filler, no severity theater.

Output fields:
- md: the Markdown body, a draft for a human, not a ruling.
- citations: cite a fact only by a real fact_id a prior gave you, copied verbatim; if you have none, return an EMPTY list. Never invent a fact_id and never put evidence fields inside a citation object.""",
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
        data_block("EVIDENCE", ev.model_dump_json())
        + data_block("CONFIRMED", json.dumps(confirmed or []))
        + "Draft the analyst-facing Markdown report from the confirmed items only. "
        "Return the structured report."
    )


async def run(ev: Evidence, confirmed: list[str] | None = None) -> Report:
    """Run the report writer end to end and return its typed report."""
    agent = build_report_writer()
    result = await agent.run(report_prompt(ev, confirmed))
    return result.output
