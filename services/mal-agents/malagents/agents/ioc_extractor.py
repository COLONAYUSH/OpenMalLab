"""The IOC-extractor agent: distill defanged evidence into typed indicators.

It reasons over a defanged, structured Evidence projection - decoded strings,
engine details, and paths - and returns a TYPED IOCSet: deduped, classified
indicators (url, ip, domain, mutex, registry, file). IOCs are leads, never
verdicts; the typed output is coerced to a schema here, then re-validated and
gated on the Go side. Evidence is passed as DATA in a delimited block, never
concatenated into the instruction; the extractor can only surface indicators that
are actually present in the evidence, and it fabricates nothing.
"""

from __future__ import annotations

from pydantic_ai import Agent

from ..models import Evidence
from ._prompts import system
from .factory import make_agent
from .schemas import IOCSet

SYSTEM_PROMPT = system(
    'You are an INDICATOR-OF-COMPROMISE extraction specialist. You distill hostile evidence into a clean, typed, deduplicated indicator set analysts can pivot and block on.',
    """Method: scan the decoded strings, engine details, and paths, and surface every indicator ACTUALLY PRESENT in the evidence as a typed IOC. Fabricate nothing; if there are none, return an empty set.

Classify each by its MOST SPECIFIC type: url, ip, domain, mutex, registry, or file:
- a full scheme+host+path is a url; a bare hostname is a domain; a dotted or colon-separated numeric literal is an ip.
- name pipe/event/mutex objects as mutex; HKLM/HKCU-style keys as registry; on-disk names or paths as file.

Deduplicate identical indicators, judging identity AFTER ignoring defang markers (treat hxxp as http and [.] as a dot). Keep each value as it appears in the evidence. These are LEADS for pivoting and blocking, never verdicts.""",
)


def build_ioc_extractor() -> Agent[None, IOCSet]:
    """Construct the IOC-extractor agent over the configured model (test model offline)."""
    return make_agent(IOCSet, SYSTEM_PROMPT)


def evidence_prompt(ev: Evidence) -> str:
    """Wrap the evidence as DATA in a delimited block - never as instructions."""
    return "<EVIDENCE>\n" + ev.model_dump_json() + "\n</EVIDENCE>\nReturn the structured IOC set."


async def run(ev: Evidence) -> IOCSet:
    """Run the IOC-extractor agent end to end and return its typed IOC set."""
    agent = build_ioc_extractor()
    result = await agent.run(evidence_prompt(ev))
    return result.output
