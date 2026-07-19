"""Tiers 2 and 3 of the self-improving loop (design sec 09), offline and gated.

Tier 2 (DSPy prompt optimization) and tier 3 (LoRA fine-tuning) both change model
BEHAVIOR, so - unlike tier-1 retrieval memory - they are the durable-influence
surfaces the cross-time poisoning threat (THREAT #1) targets. this module is the
GATE around them, not the optimizer/trainer themselves: those are heavy
(DSPy / GPU, ASK.md LEARN-1/2) and PLUGGABLE - they only PRODUCE a candidate. a
candidate is promoted to the active version ONLY if it is:

  1. built from HUMAN-VALIDATED data (no auto-labeled examples), and
  2. HUMAN-APPROVED (a privileged release, never an autonomous loop), and
  3. it BEATS the incumbent on an IMMUTABLE holdout eval.

every promotion is recorded and one-click reversible (rollback). the producer and
scorer are injected, so the whole gate is exercised offline with deterministic
mocks; wiring a real DSPy optimizer or LoRA trainer changes nothing about the gate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable


@dataclass
class Example:
    """One holdout example. human_validated MUST be true for it to gate a release
    (a system that learns from hostile samples must not grade itself on them)."""

    prompt: str
    expected: str
    human_validated: bool = False


@dataclass
class Version:
    """A prompt (tier 2) or model (tier 3) version. score is its holdout score at
    promotion time; approved is the human release sign-off. artifact is the gradeable
    thing (the prompt text / model handle), RETAINED so the incumbent can be
    re-scored on a later holdout rather than trusting its stale promotion-time score."""

    id: str
    kind: str  # "prompt" | "model"
    score: float = 0.0
    approved: bool = False
    artifact: object = None


# a Scorer grades a candidate artifact against the holdout, returning [0,1] accuracy.
Scorer = Callable[[object, "list[Example]"], float]


@dataclass
class Registry:
    """Versioned artifacts with rollback. `active` is what ships; `history` is the
    ordered promotion log."""

    history: list[Version] = field(default_factory=list)
    active: Version | None = None

    def promote(self, v: Version) -> None:
        self.history.append(v)
        self.active = v

    def rollback(self) -> Version | None:
        # one-click revert to the previous promoted version.
        if len(self.history) < 2:
            return None
        self.history.pop()
        self.active = self.history[-1]
        return self.active

    def incumbent_score(self) -> float:
        return self.active.score if self.active else 0.0


def gate_promotion(candidate: Version, artifact: object, holdout: list[Example],
                   incumbent_score: float, scorer: Scorer) -> tuple[bool, str]:
    """The promotion gate. returns (promote?, reason). fail-closed on every check.

    a candidate ships ONLY if the holdout is entirely human-validated, the
    candidate is human-approved, and it strictly beats the incumbent's score.
    """
    if not holdout:
        return False, "no holdout eval set"
    if not all(e.human_validated for e in holdout):
        return False, "holdout contains unvalidated data"
    if not candidate.approved:
        return False, "candidate is not human-approved"
    candidate.score = scorer(artifact, holdout)
    if candidate.score <= incumbent_score:
        return False, "candidate does not beat the incumbent (%.3f <= %.3f)" % (candidate.score, incumbent_score)
    return True, "promoted: %.3f > incumbent %.3f, validated + approved" % (candidate.score, incumbent_score)


def run_learning(registry: Registry, candidate: Version, artifact: object,
                 holdout: list[Example], scorer: Scorer) -> tuple[bool, str]:
    """Run one offline tier-2/3 cycle: gate the produced candidate against the
    registry's incumbent and promote it only if the gate passes. the producer
    (DSPy optimizer or LoRA trainer) has already made `candidate`/`artifact`; this
    is the release control. returns (promoted?, reason).

    The incumbent is RE-SCORED on the CURRENT holdout before the comparison, not
    judged by the score it earned at its own promotion time. Holdouts grow and
    change; comparing a fresh candidate score to a stale incumbent score is apples
    to oranges and can promote a worse model (or block a better one). Both sides are
    now graded by the same scorer on the same eval set. The candidate's artifact is
    retained on its Version so it in turn can be re-scored when it is the incumbent."""
    candidate.artifact = artifact
    inc = registry.active
    incumbent_score = scorer(inc.artifact, holdout) if inc is not None else 0.0
    ok, reason = gate_promotion(candidate, artifact, holdout, incumbent_score, scorer)
    if ok:
        registry.promote(candidate)
    return ok, reason
