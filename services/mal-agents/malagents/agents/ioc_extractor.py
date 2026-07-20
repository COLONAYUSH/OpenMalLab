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
from ._prompts import data_block, system
from .factory import make_agent
from .schemas import IOCSet

SYSTEM_PROMPT = system(
    'You are an INDICATOR-OF-COMPROMISE extraction specialist. You distill hostile evidence into a clean, typed, deduplicated indicator set analysts can pivot and block on.',
    """Method - extract, classify, dedupe; in that order:
1. EXTRACT: scan the decoded strings, engine details, and paths, and surface every indicator ACTUALLY PRESENT in the evidence. Copy each value exactly as it appears, defanged form preserved (hxxp stays hxxp, [.] stays [.]). Fabricate nothing, and NEVER repair the data: do not complete a truncated URL, resolve a domain to an IP, guess a scheme, or normalize a path. A fragment too broken to classify is not an IOC.
2. CLASSIFY by the MOST SPECIFIC type: url, ip, domain, mutex, registry, or file.
   - a full scheme+host(+path) is a url; a bare hostname is a domain; a dotted or colon-separated numeric literal is an ip. When a url is present, do not ALSO emit its host as a separate domain unless the host appears independently in the evidence.
   - named pipe/event/mutex objects are mutex; HKLM/HKCU-style keys are registry; on-disk names or paths are file.
3. DEDUPE: judge identity AFTER ignoring defang markers (hxxp equals http, [.] equals a dot), then keep ONE entry, valued as it first appears in the evidence.

An evidence set with no indicators yields an EMPTY set - that is a correct, honest extraction, never a failure. These are LEADS for pivoting and blocking; you attach no verdict, no severity, no attribution to them.""",
)


def build_ioc_extractor() -> Agent[None, IOCSet]:
    """Construct the IOC-extractor agent over the configured model (test model offline)."""
    return make_agent(IOCSet, SYSTEM_PROMPT)


def evidence_prompt(ev: Evidence) -> str:
    """Wrap the evidence as DATA in a delimited block - never as instructions."""
    return data_block("EVIDENCE", ev.model_dump_json()) + "Return the structured IOC set."


async def run(ev: Evidence) -> IOCSet:
    """Run the IOC-extractor agent end to end and return its typed IOC set."""
    agent = build_ioc_extractor()
    result = await agent.run(evidence_prompt(ev))
    return result.output
