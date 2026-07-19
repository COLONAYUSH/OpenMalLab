"""Typed outputs for the agent roster (design sec 04).

Each roster agent emits ONE of these types. They are the contract between the
agents and the Temporal agent-graph that orchestrates them: typed, bounded, and
carrying citations by fact_id where a claim rests on a known fact. None of them
is a verdict - the Go confidence gate adjudicates, the deterministic lattice
disposes. Reuses the core contract types (Citation/Hypothesis/ProposedIOC) so a
roster proposal folds into the same Proposal the Go validator checks.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from ..models import Citation, ProposedIOC


class Plan(BaseModel):
    """Router: which roster agents to spawn for this artifact, and the budget."""

    agents: list[str] = Field(default_factory=list)
    budget_tokens: int = 0
    rationale: str = ""


class Prior(BaseModel):
    """One retrieved prior from the knowledge tiers. fact_id is set only when it
    resolves to an L0 curated fact (then it is citable); otherwise it is context."""

    kind: str
    key: str
    relation: str = ""
    confidence: str = "LOW"
    fact_id: str = ""


class Priors(BaseModel):
    """Correlator: priors retrieved from the knowledge graph for this artifact."""

    priors: list[Prior] = Field(default_factory=list)


class Behavior(BaseModel):
    """One behavior narrative grounded in capa/ATT&CK evidence + priors."""

    ttp: str = ""
    why: str = ""
    citations: list[Citation] = Field(default_factory=list)


class Behaviors(BaseModel):
    """Capability reasoner: behavior narratives from capability evidence."""

    behaviors: list[Behavior] = Field(default_factory=list)


class IOCSet(BaseModel):
    """IOC extractor: typed, deduped, classified indicators (leads, not verdicts)."""

    iocs: list[ProposedIOC] = Field(default_factory=list)


class FamilyHypothesis(BaseModel):
    """Config/family hypothesizer: a proposed family + config fields, cited."""

    family: str = ""
    fields: dict[str, str] = Field(default_factory=dict)
    confidence: str = "LOW"
    citations: list[Citation] = Field(default_factory=list)


class Novelty(BaseModel):
    """Novelty detector: how unlike anything in the graph this artifact is."""

    score: float = 0.0  # 0..1, higher = more novel
    nearest: str = ""


class Verdict(BaseModel):
    """Adversarial verifier: did a hypothesis survive an attempt to REFUTE it."""

    real: bool = False
    reason: str = ""


class Report(BaseModel):
    """Report writer: the analyst-facing narrative, from confirmed items only."""

    md: str = ""
    citations: list[Citation] = Field(default_factory=list)


class Escalation(BaseModel):
    """Escalation agent: the packaged question + options for a human."""

    question: str = ""
    options: list[str] = Field(default_factory=list)
