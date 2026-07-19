"""The config/family hypothesizer agent.

It reads the defanged Evidence projection (decoded strings and other findings a
deterministic pipeline already produced) plus any PRIORS retrieved from the
knowledge graph, and returns a TYPED FamilyHypothesis: a proposed malware family,
any configuration fields the strings and priors support, a self-reported
confidence, and citations by fact_id. Family attribution is high-stakes, so the
output is only a PROPOSAL the Go confidence gate will escalate - never a verdict.
Evidence and priors are passed as DATA in delimited blocks, never concatenated
into the instruction; the model can only propose.
"""

from __future__ import annotations

from pydantic_ai import Agent

from ..models import Evidence
from ._prompts import system
from .factory import make_agent
from .schemas import FamilyHypothesis, Priors

SYSTEM_PROMPT = system(
    'You are a MALWARE FAMILY and CONFIGURATION analyst. You attribute an artifact to a known family and extract its operational config - and because attribution is high-stakes, you do it conservatively.',
    """Method: weigh the distinctive signals - string constants, mutex and campaign patterns, C2 structure, packer, imphash, and any priors - and propose the single most likely family plus the config the evidence supports.

- family: the most likely family. If no SPECIFIC family matches but the evidence fits a broad class, name that class as a lead (e.g. 'generic HTTP RAT', 'commodity loader', 'injector') at LOW confidence. Leave it empty only when the evidence is truly featureless.
- fields: config key/value pairs the evidence supports (e.g. c2, campaign_id, mutex, key). Include only fields grounded in the evidence.
- confidence: HIGH only on a signature-grade match (a distinctive, family-specific constant or config layout); MEDIUM on several corroborating traits; LOW on a single generic trait. Prefer a lower confidence over an uncited guess.
- citations: cite priors and known facts by fact_id when you have them.

Family attribution is ALWAYS a proposal the gate escalates to a human, never an autonomous verdict - however strong the match looks.""",
)


def build_family_hypothesizer() -> Agent[None, FamilyHypothesis]:
    """Construct the family hypothesizer over the configured model (test model offline)."""
    return make_agent(FamilyHypothesis, SYSTEM_PROMPT)


def hypothesis_prompt(ev: Evidence, priors: Priors | None = None) -> str:
    """Wrap the evidence, and any priors, as DATA in delimited blocks - never as
    instructions. Hostile text inside the blocks is only ever data to analyze."""
    blocks = "<EVIDENCE>\n" + ev.model_dump_json() + "\n</EVIDENCE>\n"
    if priors is not None:
        blocks += "<PRIORS>\n" + priors.model_dump_json() + "\n</PRIORS>\n"
    return blocks + "Return the structured family hypothesis."


async def run(ev: Evidence, priors: Priors | None = None) -> FamilyHypothesis:
    """Run the family hypothesizer end to end and return its typed hypothesis."""
    agent = build_family_hypothesizer()
    result = await agent.run(hypothesis_prompt(ev, priors))
    return result.output
