"""The tier-2/3 promotion gate: the release control that stops a wrong or hostile
lesson from becoming a durable model behavior. every guard fails closed."""

from malagents.learning import Example, Registry, Version, gate_promotion, run_learning


def validated_holdout(n=5):
    return [Example(prompt=f"p{i}", expected=f"e{i}", human_validated=True) for i in range(n)]


# a scorer that returns a fixed accuracy regardless of the artifact (deterministic).
def fixed_scorer(score):
    return lambda _artifact, _holdout: score


def test_gate_rejects_unvalidated_holdout():
    bad = [Example("p", "e", human_validated=False)]
    ok, reason = gate_promotion(Version("v1", "prompt", approved=True), None, bad, 0.0, fixed_scorer(1.0))
    assert not ok and "unvalidated" in reason


def test_gate_rejects_unapproved_candidate():
    ok, reason = gate_promotion(Version("v1", "prompt", approved=False), None, validated_holdout(), 0.0, fixed_scorer(1.0))
    assert not ok and "approved" in reason


def test_gate_rejects_candidate_not_beating_incumbent():
    # candidate scores 0.7, incumbent is already 0.8: must not ship.
    ok, reason = gate_promotion(Version("v2", "prompt", approved=True), None, validated_holdout(), 0.8, fixed_scorer(0.7))
    assert not ok and "does not beat" in reason


def test_gate_accepts_validated_approved_better_candidate():
    ok, reason = gate_promotion(Version("v2", "prompt", approved=True), None, validated_holdout(), 0.8, fixed_scorer(0.9))
    assert ok, reason


# an artifact-dependent scorer: the artifact maps a holdout's size (a proxy for its
# identity) to the accuracy that artifact achieves on it. This models a real eval,
# where the SAME artifact scores differently across different holdouts - which is
# exactly what makes re-scoring the incumbent necessary.
def acc_scorer(artifact, holdout):
    return artifact.get(len(holdout), 0.0) if isinstance(artifact, dict) else 0.0


def test_run_learning_promotes_and_rolls_back():
    reg = Registry()
    h = validated_holdout(5)
    # first release: from a zero incumbent, an approved 0.8 candidate ships.
    ok, _ = run_learning(reg, Version("v1", "model", approved=True), {5: 0.8}, h, acc_scorer)
    assert ok and reg.active.id == "v1"
    # a better candidate (0.9 > the incumbent's re-scored 0.8) ships.
    ok, _ = run_learning(reg, Version("v2", "model", approved=True), {5: 0.9}, h, acc_scorer)
    assert ok and reg.active.id == "v2"
    # a regression (0.85 < the incumbent's re-scored 0.9) is rejected; active unchanged.
    ok, _ = run_learning(reg, Version("v3", "model", approved=True), {5: 0.85}, h, acc_scorer)
    assert not ok and reg.active.id == "v2"
    # one-click rollback reverts to the prior version.
    reverted = reg.rollback()
    assert reverted is not None and reg.active.id == "v1"


def test_run_learning_rescores_incumbent_on_current_holdout():
    # finding #20: the incumbent must be re-scored on the CURRENT holdout, not judged
    # by its stale promotion-time score.
    reg = Registry()
    easy = validated_holdout(5)   # the incumbent looked great here...
    hard = validated_holdout(10)  # ...but the holdout has since grown harder.

    # incumbent promoted on the EASY holdout: it stores a 0.9. on the HARD holdout its
    # true accuracy is only 0.6.
    ok, _ = run_learning(reg, Version("inc", "model", approved=True), {5: 0.9, 10: 0.6}, easy, acc_scorer)
    assert ok and reg.active.score == 0.9

    # a candidate scores 0.7 on the current (hard) holdout: BELOW the incumbent's
    # stored 0.9, but ABOVE the incumbent's TRUE score on this holdout (0.6).
    ok, reason = run_learning(reg, Version("cand", "model", approved=True), {10: 0.7}, hard, acc_scorer)
    # the fix re-scores the incumbent to 0.6, so 0.7 > 0.6 -> promote. the bug (compare
    # against the stored 0.9) would have wrongly rejected a genuinely better model.
    assert ok, reason
    assert reg.active.id == "cand"
