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

from pydantic import BaseModel, Field

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


class Citation(BaseModel):
    """A fact the agent cites for a claim (mirrors aiplane.Citation).

    The Go gate re-resolves ``fact_id`` against the L0 registry and confirms it is
    bound to ``(kind, key)`` - the agent cannot fabricate a citation, and these
    fields are passed BYTE-FOR-BYTE (never mutated) so a real curated key resolves.
    """

    fact_id: str = Field(
        description="the fact_id of a known fact, taken VERBATIM from a prior; never "
        "invent one. If you have no real fact_id, do not emit a citation at all."
    )
    kind: str = Field(description="the fact's kind, e.g. 'attck' or 'family'.")
    key: str = Field(description="the fact's key, e.g. the technique id 'T1055'.")


class Hypothesis(BaseModel):
    """One proposed conclusion (mirrors aiplane.Hypothesis).

    ``confidence`` is the model's SELF-report and is advisory only; the Go gate
    recalibrates it against measured accuracy and can only ever lower the outcome.
    """

    kind: str
    claim: str
    confidence: str = "LOW"
    citations: list[Citation] = Field(default_factory=list)


class ProposedIOC(BaseModel):
    """An indicator the agent surfaces - a lead, never a verdict."""

    type: str
    value: str


class Proposal(BaseModel):
    """The AI plane's typed, UNTRUSTED output (mirrors aiplane.Proposal).

    Deliberately carries no submission id: the caller knows which submission it
    dispatched, so the model cannot misattribute its output (confused deputy).
    """

    summary: str = ""
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    iocs: list[ProposedIOC] = Field(default_factory=list)
    needs_review: bool = False
    review_reason: str = ""
