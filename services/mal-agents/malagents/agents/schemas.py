"""Typed outputs for the agent roster (design sec 04).

Each roster agent emits ONE of these types. They are the contract between the
agents and the Temporal agent-graph that orchestrates them: typed, bounded, and
carrying citations by fact_id where a claim rests on a known fact. None of them
is a verdict - the Go confidence gate adjudicates, the deterministic lattice
disposes. Reuses the core contract types (Citation/Hypothesis/ProposedIOC) so a
roster proposal folds into the same Proposal the Go validator checks.

Two postures live here, and the difference is deliberate:

- OUTPUT-ONLY schemas (Plan, Behaviors, IOCSet, FamilyHypothesis, Novelty,
  Verdict, Report, Escalation) extend StrictOutput: an unknown field name from
  the model is a hard validation error the retry loop feeds back, never a
  silently-kept default (a real past bug).
- Prior/Priors are BOTH an agent output and a spine INPUT (the Go agent-graph
  retrieves priors from the knowledge tiers and hands them back to the
  reasoners), so they stay lenient to extras: the trusted Go side must be able
  to grow a field before this service redeploys.

Field bounds mirror the Go contract constants so a runaway model fails fast
here with a self-correcting validation error instead of late on the Go side.
"""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from ..models import (
    MAX_CITATIONS,
    MAX_CLAIM,
    MAX_FIELD,
    MAX_HYPOTHESES,
    MAX_IOCS,
    MAX_SUMMARY,
    Citation,
    Confidence,
    ProposedIOC,
    StrictOutput,
)

# roster-local bounds (the Go agent-graph re-bounds everything it reads anyway).
MAX_PLAN_AGENTS = 16  # the roster is 10 names; anything past this is babble
MAX_PRIORS = 256
MAX_BEHAVIORS = MAX_HYPOTHESES  # each behavior folds into one hypothesis
MAX_CONFIG_FIELDS = 32
MAX_OPTIONS = 4  # the escalation brief asks for 2 to 4 options
MAX_BUDGET_TOKENS = 1_000_000


class Plan(StrictOutput):
    """Router: which roster agents to spawn for this artifact, and the budget."""

    agents: list[str] = Field(
        default_factory=list,
        max_length=MAX_PLAN_AGENTS,
        description="the roster agent names to spawn, lowercase, e.g. "
        "['correlator', 'novelty_detector', 'capability_reasoner']. Only names "
        "from the roster you were briefed on; the spine ignores anything else.",
    )
    budget_tokens: int = Field(
        0,
        ge=0,
        le=MAX_BUDGET_TOKENS,
        description="a rough total token budget sized to the work actually "
        "proposed; do not pad it.",
    )
    rationale: str = Field(
        "",
        max_length=MAX_CLAIM,
        description="one or two lines on why these agents and this budget, citing "
        "a fact_id only if a prior actually drove a choice.",
    )

    @field_validator("agents")
    @classmethod
    def _normalized_names(cls, v: list[str]) -> list[str]:
        # normalize what we can without guessing: trim, lowercase, drop empties,
        # dedupe preserving order. Unknown names are kept - the spine's allow-list
        # is the authority on what exists, and silently dropping here would hide a
        # misbehaving model from it.
        seen: set[str] = set()
        out: list[str] = []
        for name in v:
            n = name.strip().lower()
            if n and n not in seen:
                seen.add(n)
                out.append(n)
        return out


class Prior(BaseModel):
    """One retrieved prior from the knowledge tiers. fact_id is set only when it
    resolves to an L0 curated fact (then it is citable); otherwise it is context.

    Lenient to extra fields on purpose: the spine sends priors TO the reasoners
    (see the module docstring), and it may carry fields this service predates.
    """

    kind: str = Field(
        min_length=1,
        max_length=MAX_FIELD,
        description="what kind of thing this prior names: family, c2, packer, "
        "technique, imphash, or another short lowercase token the tiers use "
        "(e.g. 'attck').",
    )
    key: str = Field(
        min_length=1,
        max_length=MAX_FIELD,
        description="the exact value to look up or that was looked up: a family "
        "name, a defanged C2 host or URL, a packer name, an ATT&CK id like "
        "'T1055', or an imphash.",
    )
    relation: str = Field(
        "",
        max_length=MAX_FIELD,
        description="how the artifact relates to it, e.g. 'beacons to', "
        "'packed with', 'resembles'.",
    )
    confidence: Confidence = Field(
        "LOW",
        description="confidence in the RESEMBLANCE, per the calibration rule.",
    )
    fact_id: str = Field(
        "",
        max_length=MAX_FIELD,
        description="the L0 fact id when this prior resolves to a curated fact "
        "(then it is citable, verbatim). Empty for a hint or a fuzzy lead; NEVER "
        "an invented value.",
    )
    tier: str = Field(
        "",
        max_length=MAX_FIELD,
        description="which knowledge tier produced this prior (e.g. 'L0' exact, "
        "'L0.5' fuzzy). Set by the spine's retrieval; leave empty when proposing.",
    )


class Priors(BaseModel):
    """Correlator: priors retrieved from (or proposed to) the knowledge graph for
    this artifact. Lenient to extras for the same reason as Prior."""

    priors: list[Prior] = Field(
        default_factory=list,
        description="the priors, strongest pivots first. An artifact with nothing "
        "distinctive yields an empty list - that is a valid, honest answer.",
    )

    @field_validator("priors")
    @classmethod
    def _bounded_priors(cls, v: list[Prior]) -> list[Prior]:
        # input posture: Priors also ARRIVES from the spine, so an over-long list
        # is truncated (bounded acceptance, like the Go clean()) rather than
        # rejected - failing the whole enrichment over tail hints helps no one.
        return v[:MAX_PRIORS]


class Behavior(StrictOutput):
    """One behavior narrative grounded in capa/ATT&CK evidence + priors."""

    ttp: str = Field(
        default="",
        max_length=MAX_FIELD,
        description="the ATT&CK technique id this behavior maps to, e.g. 'T1055' "
        "or 'T1055.012'. Copy it VERBATIM from the evidence's attck field, "
        "sub-technique suffix included; never invent one and never emit a "
        "behavior for evidence that carries no technique id.",
    )
    why: str = Field(
        default="",
        max_length=MAX_CLAIM,
        description="one line of plain analyst language explaining the behavior, "
        "grounded in the specific evidence item that shows it.",
    )
    citations: list[Citation] = Field(
        default_factory=list,
        max_length=MAX_CITATIONS,
        description="facts this behavior rests on. Include a citation ONLY when a "
        "prior gives you a real fact_id; otherwise leave this list empty.",
    )


class Behaviors(StrictOutput):
    """Capability reasoner: behavior narratives from capability evidence."""

    behaviors: list[Behavior] = Field(
        default_factory=list,
        max_length=MAX_BEHAVIORS,
        description="one Behavior per DISTINCT technique in the evidence "
        "(duplicates collapsed); empty when the evidence carries no capability "
        "signal.",
    )


class IOCSet(StrictOutput):
    """IOC extractor: typed, deduped, classified indicators (leads, not verdicts)."""

    iocs: list[ProposedIOC] = Field(
        default_factory=list,
        max_length=MAX_IOCS,
        description="every indicator actually present in the evidence, deduped "
        "after ignoring defang markers; empty when there are none.",
    )


class FamilyHypothesis(StrictOutput):
    """Config/family hypothesizer: a proposed family + config fields, cited."""

    family: str = Field(
        "",
        max_length=MAX_FIELD,
        description="the most likely family, or a broad CLASS as a lead (e.g. "
        "'generic HTTP RAT') when no specific family is supported. Empty only "
        "when the evidence is truly featureless.",
    )
    fields: dict[str, str] = Field(
        default_factory=dict,
        description="extracted config key/value pairs (e.g. c2, campaign_id, "
        "mutex, key), each grounded in a specific evidence string; never padded "
        "with guesses.",
    )
    confidence: Confidence = Field(
        "LOW",
        description="HIGH only on a family-specific, signature-grade match; "
        "MEDIUM on several corroborating traits; LOW on a single or generic "
        "trait, and ALWAYS for a class-level lead.",
    )
    citations: list[Citation] = Field(
        default_factory=list,
        max_length=MAX_CITATIONS,
        description="priors and known facts by real fact_id only; empty when "
        "nothing citable grounds the attribution.",
    )

    @field_validator("fields")
    @classmethod
    def _bounded_fields(cls, v: dict[str, str]) -> dict[str, str]:
        # a config extraction is a handful of short tokens; a giant map is a
        # runaway or hostile output, so reject it (the retry loop reports why).
        if len(v) > MAX_CONFIG_FIELDS:
            raise ValueError("too many config fields (max %d)" % MAX_CONFIG_FIELDS)
        for k, val in v.items():
            if len(k) > MAX_FIELD or len(val) > MAX_FIELD:
                raise ValueError("config field key/value too long (max %d chars)" % MAX_FIELD)
        return v


class Novelty(StrictOutput):
    """Novelty detector: how unlike anything in the graph this artifact is."""

    score: float = Field(
        0.0,
        ge=0.0,
        le=1.0,
        description="0.0-0.3 commodity or recognizable; 0.3-0.7 a partly-unusual "
        "combination; 0.7-1.0 matches little or nothing known. Higher drives "
        "escalation, so never inflate it; sparse evidence is uncertainty, not "
        "novelty.",
    )
    nearest: str = Field(
        "",
        max_length=MAX_FIELD,
        description="the closest known thing (a family, technique, tool, or a "
        "prior by its fact_id); state plainly when nothing is close.",
    )


class Verdict(StrictOutput):
    """Adversarial verifier: did a hypothesis survive an attempt to REFUTE it."""

    real: bool = Field(
        False,
        description="true ONLY when a specific evidence item genuinely supports "
        "the claim. false whenever the evidence is silent, ambiguous, merely "
        "consistent-with, or you are unsure: the default answer is NOT PROVEN.",
    )
    reason: str = Field(
        "",
        max_length=MAX_CLAIM,
        description="for true: the specific evidence item(s) that support the "
        "claim. For false: exactly what support is missing.",
    )


class Report(StrictOutput):
    """Report writer: the analyst-facing narrative, from confirmed items only."""

    md: str = Field(
        "",
        max_length=MAX_SUMMARY,
        description="the Markdown body - a draft for a human, not a ruling; built "
        "from the confirmed items and ground-truth evidence only.",
    )
    citations: list[Citation] = Field(
        default_factory=list,
        max_length=MAX_CITATIONS,
        description="real fact_ids the report leans on; empty when it cites "
        "nothing curated.",
    )


class Escalation(StrictOutput):
    """Escalation agent: the packaged question + options for a human."""

    question: str = Field(
        "",
        max_length=MAX_CLAIM,
        description="ONE specific, answerable question capturing exactly what the "
        "human must decide - the concrete fork the evidence poses, not 'is this "
        "bad?'.",
    )
    options: list[str] = Field(
        default_factory=list,
        max_length=MAX_OPTIONS,
        description="2 to 4 concrete, mutually-distinct actions the reviewer can "
        "pick between, each grounded in the evidence or the escalation reason.",
    )

    @field_validator("options")
    @classmethod
    def _bounded_options(cls, v: list[str]) -> list[str]:
        for opt in v:
            if len(opt) > MAX_CLAIM:
                raise ValueError("escalation option too long (max %d chars)" % MAX_CLAIM)
        return v
