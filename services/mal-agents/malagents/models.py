"""The Go<->Python contract for the AI-analyst plane.

These Pydantic models mirror the Go ``internal/aiplane`` types field-for-field
(JSON names included), so the typed object a Pydantic-AI agent produces serializes
to exactly the ``Proposal`` the Go ``Validate`` + confidence gate adjudicate. The
Python side is the reasoning muscle; the Go side stays the trusted adjudicator, so
these models are a serialization + typing convenience, NOT a trust boundary. The
Go validator remains authoritative: anything these models let through is still
strictly re-checked, bounded, defanged, and gated on the Go side.

Kept deliberately small and dependency-light (pydantic only) to stay auditable in
the air-gapped plane.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, field_validator

# Bounds mirror the Go contract (internal/aiplane/contract.go). They are advisory
# here - the Go validator enforces them for real - but keeping them in sync makes
# the agent fail fast and keeps the two sides honest.
MAX_SUMMARY = 8192
MAX_CLAIM = 2048
MAX_FIELD = 512
MAX_HYPOTHESES = 64
MAX_IOCS = 256
MAX_CITATIONS = 32
MAX_EVIDENCE_ITEMS = 2000

CONFIDENCE = ("LOW", "MEDIUM", "HIGH")


def _upper_token(v):
    """Case-normalize a confidence token before validation. A real local model has
    been observed emitting 'medium' (see internal/aiplane/testdata); the Go gate
    upper-cases too (normConfidence), so tolerate case while still rejecting a
    made-up token like 'CERTAIN' - the validation error feeds back through the
    pydantic-ai retry loop and the model self-corrects."""
    return v.strip().upper() if isinstance(v, str) else v


# The one confidence vocabulary the whole plane speaks. A Literal (not a bare str)
# so a hallucinated token is a loud validation error, never a silently-passed
# string the Go gate then floors.
Confidence = Annotated[Literal["LOW", "MEDIUM", "HIGH"], BeforeValidator(_upper_token)]


class StrictOutput(BaseModel):
    """Base for every schema an AGENT EMITS: an unknown field name is a hard
    validation error, never silently dropped.

    This is a regression guard for a real past bug: with pydantic's default
    (ignore extras), a model answering with a mis-named field (say 'is_real'
    instead of 'real') validated fine and the real field silently kept its
    default - a wrong answer indistinguishable from a confident one. With
    extra='forbid' the mistake becomes a validation error that pydantic-ai feeds
    back to the model, which then self-corrects or fails loudly after the retry
    budget. Input models (Evidence, Prior) deliberately do NOT inherit this:
    they must stay lenient so the trusted Go side can grow fields first.
    """

    model_config = ConfigDict(extra="forbid")


class EvidenceItem(BaseModel):
    """One defanged finding the AI reasons over (mirrors aiplane.EvidenceItem)."""

    engine: str = ""
    type: str = ""
    detail: str = ""  # DEFANGED on the Go side before it ever reaches here
    attck: str = ""
    verdict: str = ""
    confidence: str = ""
    path: str = ""


class Evidence(BaseModel):
    """The defanged, bounded projection of a submission (mirrors aiplane.Evidence).

    verdict/score/confidence are deterministic GROUND TRUTH the agent must not
    contradict; every free-text field arrived already defanged from the Go side.
    """

    submission_id: str = ""
    sha256: str = ""
    file_type: str = ""
    verdict: str = ""
    score: int = 0
    confidence: str = ""
    incomplete: bool = False
    items: list[EvidenceItem] = Field(default_factory=list)


class Citation(StrictOutput):
    """A fact the agent cites for a claim (mirrors aiplane.Citation).

    The Go gate re-resolves ``fact_id`` against the L0 registry and confirms it is
    bound to ``(kind, key)`` - the agent cannot fabricate a citation, and these
    fields are passed BYTE-FOR-BYTE (never mutated) so a real curated key resolves.
    All three fields are REQUIRED and non-empty: a hollow citation is exactly the
    fabrication shape we refuse at the schema, mirroring the Go citationToken
    check (which rejects rather than cleans).
    """

    fact_id: str = Field(
        min_length=1,
        max_length=MAX_FIELD,
        description="the fact_id of a known fact, copied VERBATIM from a prior that "
        "carried it; NEVER invent, guess, or reconstruct one. If you have no real "
        "fact_id, do not emit a citation object at all - emit an empty citations "
        "list instead.",
    )
    kind: str = Field(
        min_length=1,
        max_length=MAX_FIELD,
        description="the cited fact's kind exactly as the prior gave it, e.g. "
        "'attck' or 'family'.",
    )
    key: str = Field(
        min_length=1,
        max_length=MAX_FIELD,
        description="the cited fact's key exactly as the prior gave it, e.g. the "
        "technique id 'T1055'.",
    )

    @field_validator("fact_id", "kind", "key")
    @classmethod
    def _verbatim_token(cls, v: str) -> str:
        # a citation is a content-bound handle: whitespace padding (or a
        # whitespace-only value) can only be noise or an evasion, and we must not
        # mutate the value to fix it (byte-for-byte or nothing).
        if v.strip() != v or not v.strip():
            raise ValueError("citation fields must be verbatim, non-empty, and unpadded")
        return v


class Hypothesis(StrictOutput):
    """One proposed conclusion (mirrors aiplane.Hypothesis).

    ``confidence`` is the model's SELF-report and is advisory only; the Go gate
    recalibrates it against measured accuracy and can only ever lower the outcome.
    """

    kind: str = Field(
        min_length=1,
        max_length=MAX_FIELD,
        description="the class of this conclusion: capability, technique, family, "
        "or behavior.",
    )
    claim: str = Field(
        min_length=1,
        max_length=MAX_CLAIM,
        description="the conclusion itself, one plain-language sentence grounded in "
        "the evidence.",
    )
    confidence: Confidence = Field(
        "LOW",
        description="honest self-reported confidence: HIGH only for signature-grade "
        "certainty, MEDIUM for several corroborating signals, LOW for a single weak "
        "or circumstantial one.",
    )
    citations: list[Citation] = Field(
        default_factory=list,
        max_length=MAX_CITATIONS,
        description="the known facts this claim rests on. Cite ONLY fact_ids handed "
        "to you by a prior; when nothing grounds the claim, emit an empty list.",
    )


class ProposedIOC(StrictOutput):
    """An indicator the agent surfaces - a lead, never a verdict."""

    type: str = Field(
        min_length=1,
        max_length=MAX_FIELD,
        description="the indicator's most specific type - canonically one of url, "
        "ip, domain, mutex, registry, or file; another short lowercase token only "
        "when none of those fits.",
    )
    value: str = Field(
        min_length=1,
        max_length=MAX_FIELD,
        description="the indicator value exactly as it appears in the evidence "
        "(defanged form preserved); never a value the evidence does not contain.",
    )


class Proposal(StrictOutput):
    """The AI plane's typed, UNTRUSTED output (mirrors aiplane.Proposal).

    Deliberately carries no submission id: the caller knows which submission it
    dispatched, so the model cannot misattribute its output (confused deputy).
    """

    summary: str = Field(
        "",
        max_length=MAX_SUMMARY,
        description="a tight analyst-facing paragraph of what the artifact appears "
        "to do, consistent with the deterministic verdict.",
    )
    hypotheses: list[Hypothesis] = Field(
        default_factory=list,
        max_length=MAX_HYPOTHESES,
        description="the proposed conclusions, each independently calibrated and "
        "cited.",
    )
    iocs: list[ProposedIOC] = Field(
        default_factory=list,
        max_length=MAX_IOCS,
        description="indicators actually present in the evidence; never fabricated "
        "or completed ones.",
    )
    needs_review: bool = Field(
        False,
        description="true when the evidence is thin or conflicting, or the stakes "
        "are high (family attribution, novelty); when in doubt, true.",
    )
    review_reason: str = Field(
        "",
        max_length=MAX_SUMMARY,
        description="when needs_review is true, one sentence saying exactly what a "
        "human should look at.",
    )
