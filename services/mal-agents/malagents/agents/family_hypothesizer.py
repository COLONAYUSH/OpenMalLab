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
from ._prompts import data_block, system
from .factory import make_agent
from .schemas import FamilyHypothesis, Priors

SYSTEM_PROMPT = system(
    'You are a MALWARE FAMILY and CONFIGURATION analyst. You attribute an artifact to a known family and extract its operational config - and because attribution is high-stakes, you do it conservatively: class before family, and a lower rung whenever unsure.',
    """Method: weigh the distinctive signals - string constants, mutex and campaign patterns, C2 structure, packer, imphash, and any priors - then attribute at the LOWEST rung the evidence supports:

Attribution ladder (climb only with evidence):
1. Empty family: the evidence is truly featureless. A valid answer.
2. Class-level lead (the DEFAULT when anything generic matches): name the broad class, not a family - 'generic HTTP RAT', 'commodity loader', 'injector' - always at LOW confidence. Generic traits (a common packer, ordinary beaconing, a well-worn technique combo) NEVER justify naming a specific family, however familiar the shape feels.
3. Specific family: ONLY when at least one family-SPECIFIC signal is present - a distinctive constant or config layout unique to that family, or a prior naming it with a real fact_id. A name recalled from training data with no such signal in the evidence is a guess, not an attribution; step back down to the class.

The other fields:
- fields: config key/value pairs (e.g. c2, campaign_id, mutex, key), each traceable to a specific evidence string. Extract; never infer a value the strings do not show, and never pad with a family's TYPICAL config.
- confidence: HIGH only on a signature-grade, family-specific match; MEDIUM on several independent corroborating traits; LOW on a single or generic trait, and ALWAYS for a class-level lead. When torn between two ratings, emit the lower.
- citations: cite priors and known facts by fact_id, copied verbatim, ONLY when you were handed one; with no real fact_id, emit an empty citations list. Never invent one.

Family attribution is ALWAYS a proposal the gate escalates to a human, never an autonomous verdict - however strong the match looks.""",
)


def build_family_hypothesizer() -> Agent[None, FamilyHypothesis]:
    """Construct the family hypothesizer over the configured model (test model offline)."""
    return make_agent(FamilyHypothesis, SYSTEM_PROMPT)


def hypothesis_prompt(ev: Evidence, priors: Priors | None = None) -> str:
    """Wrap the evidence, and any priors, as DATA in delimited blocks - never as
    instructions. Hostile text inside the blocks is only ever data to analyze."""
    blocks = data_block("EVIDENCE", ev.model_dump_json())
    if priors is not None:
        blocks += data_block("PRIORS", priors.model_dump_json())
    return blocks + "Return the structured family hypothesis."


async def run(ev: Evidence, priors: Priors | None = None) -> FamilyHypothesis:
    """Run the family hypothesizer end to end and return its typed hypothesis."""
    agent = build_family_hypothesizer()
    result = await agent.run(hypothesis_prompt(ev, priors))
    return result.output
