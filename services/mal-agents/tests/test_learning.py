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


def test_run_learning_promotes_and_rolls_back():
    reg = Registry()
    # first release: from a zero incumbent, an approved 0.8 candidate ships.
    ok, _ = run_learning(reg, Version("v1", "model", approved=True), None, validated_holdout(), fixed_scorer(0.8))
    assert ok and reg.active.id == "v1"
    # a better, approved candidate ships and becomes active.
    ok, _ = run_learning(reg, Version("v2", "model", approved=True), None, validated_holdout(), fixed_scorer(0.9))
    assert ok and reg.active.id == "v2"
    # a regression (0.85 < 0.9) is rejected; the active version is unchanged.
    ok, _ = run_learning(reg, Version("v3", "model", approved=True), None, validated_holdout(), fixed_scorer(0.85))
    assert not ok and reg.active.id == "v2"
    # one-click rollback reverts to the prior version.
    reverted = reg.rollback()
    assert reverted is not None and reg.active.id == "v1"
