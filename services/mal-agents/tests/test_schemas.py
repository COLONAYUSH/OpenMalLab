"""The roster output schemas are the security primitive: they must reject a
mis-named field (the silent-default bug), a fabricated citation shape, an
out-of-range score, and a hallucinated confidence token - and normalize what is
safe to normalize (a real local model has emitted lowercase 'medium'). All
offline, no model involved: these are pure contract tests."""

import pytest
from pydantic import ValidationError

from malagents.agents.schemas import (
    MAX_CONFIG_FIELDS,
    MAX_PRIORS,
    Behavior,
    Behaviors,
    Escalation,
    FamilyHypothesis,
    IOCSet,
    Novelty,
    Plan,
    Prior,
    Priors,
    Report,
    Verdict,
)
from malagents.models import (
    MAX_HYPOTHESES,
    MAX_IOCS,
    Citation,
    Hypothesis,
    Proposal,
    ProposedIOC,
)

# ---------------------------------------------------------------- field names

# one mis-named-field probe per OUTPUT schema: with pydantic's default posture
# these all validated fine and the real field silently kept its default (the
# past bug). extra='forbid' must make every one a loud ValidationError.
WRONG_FIELD_PROBES = [
    (Plan, {"agent_list": ["correlator"]}),
    (Behaviors, {"behaviours": []}),
    (Behavior, {"technique": "T1055"}),
    (IOCSet, {"indicators": []}),
    (FamilyHypothesis, {"family_name": "emotet"}),
    (Novelty, {"novelty_score": 0.9}),
    (Verdict, {"is_real": True}),
    (Report, {"markdown": "# x"}),
    (Escalation, {"choices": ["a", "b"]}),
    (Proposal, {"summary_text": "x"}),
    (Hypothesis, {"kind": "family", "claim": "x", "conf": "HIGH"}),
    (ProposedIOC, {"type": "url", "value": "hxxp://x", "severity": "high"}),
    (Citation, {"fact_id": "kf_1", "kind": "attck", "key": "T1055", "note": "x"}),
]


@pytest.mark.parametrize("model,payload", WRONG_FIELD_PROBES, ids=lambda p: getattr(p, "__name__", ""))
def test_unknown_field_names_fail_loudly(model, payload):
    with pytest.raises(ValidationError):
        model.model_validate(payload)


def test_wrong_field_name_cannot_silently_keep_the_default():
    # the exact bug shape: a model answers {'is_real': true} and a lenient schema
    # would return Verdict(real=False) - a refutation the model never made. That
    # output must be impossible to construct.
    with pytest.raises(ValidationError):
        Verdict.model_validate({"is_real": True, "reason": "looks right"})


# ---------------------------------------------------------------- confidence

def test_confidence_case_is_normalized():
    # mirrors internal/aiplane/testdata/live_proposal_gptoss120b.json: a real
    # local model emitted 'medium'; the Go gate upper-cases, so we must too.
    assert Hypothesis(kind="family", claim="x", confidence="medium").confidence == "MEDIUM"
    assert Prior(kind="family", key="k", confidence=" high ").confidence == "HIGH"
    assert FamilyHypothesis(confidence="low").confidence == "LOW"


def test_hallucinated_confidence_token_is_rejected():
    for bad in ("CERTAIN", "VERY HIGH", "0.9", ""):
        with pytest.raises(ValidationError):
            Hypothesis(kind="family", claim="x", confidence=bad)


# ---------------------------------------------------------------- citations

def test_fabricated_citation_shapes_are_rejected():
    # the schema cannot know whether a fact_id is real (the Go gate re-resolves
    # it), but it CAN refuse the fabrication shapes: hollow, blank, or padded
    # values that would never match a curated fact byte-for-byte.
    for bad in ({"fact_id": "", "kind": "attck", "key": "T1055"},
                {"fact_id": "   ", "kind": "attck", "key": "T1055"},
                {"fact_id": " kf_1", "kind": "attck", "key": "T1055"},
                {"fact_id": "kf_1 ", "kind": "attck", "key": "T1055"},
                {"fact_id": "kf_1", "kind": "", "key": "T1055"},
                {"fact_id": "kf_1", "kind": "attck", "key": ""},
                {"kind": "attck", "key": "T1055"}):
        with pytest.raises(ValidationError):
            Citation.model_validate(bad)


def test_real_citation_passes_byte_for_byte():
    c = Citation(fact_id="kf_1", kind="attck", key="T1055")
    assert (c.fact_id, c.kind, c.key) == ("kf_1", "attck", "T1055")
    # a curated key may legitimately carry scheme tokens (a C2 url): preserved.
    c2 = Citation(fact_id="kf_9", kind="c2", key="http://203.0.113.5/gate.php")
    assert c2.key == "http://203.0.113.5/gate.php"


def test_empty_citations_list_is_the_ungrounded_answer():
    # 'emit empty citations when nothing grounds it' must be representable and
    # the default everywhere a citations list exists.
    assert Behavior().citations == []
    assert FamilyHypothesis().citations == []
    assert Report().citations == []
    assert Hypothesis(kind="capability", claim="x").citations == []


# ---------------------------------------------------------------- bounds

def test_novelty_score_bounds():
    assert Novelty(score=0.0).score == 0.0
    assert Novelty(score=1.0).score == 1.0
    for bad in (-0.1, 1.5, 100):
        with pytest.raises(ValidationError):
            Novelty(score=bad)


def test_proposal_list_caps_mirror_the_go_contract():
    hyp = {"kind": "capability", "claim": "x", "confidence": "LOW", "citations": []}
    Proposal.model_validate({"hypotheses": [hyp] * MAX_HYPOTHESES})  # at the cap: fine
    with pytest.raises(ValidationError):
        Proposal.model_validate({"hypotheses": [hyp] * (MAX_HYPOTHESES + 1)})
    ioc = {"type": "url", "value": "hxxp://x"}
    Proposal.model_validate({"iocs": [ioc] * MAX_IOCS})
    with pytest.raises(ValidationError):
        Proposal.model_validate({"iocs": [ioc] * (MAX_IOCS + 1)})


def test_oversized_claim_and_md_are_rejected():
    with pytest.raises(ValidationError):
        Hypothesis(kind="capability", claim="x" * 3000)
    with pytest.raises(ValidationError):
        Report(md="x" * 10000)


def test_family_config_fields_are_bounded():
    ok = FamilyHypothesis(fields={"c2": "hxxp://evil.example/gate"})
    assert ok.fields["c2"].startswith("hxxp")
    with pytest.raises(ValidationError):
        FamilyHypothesis(fields={f"k{i}": "v" for i in range(MAX_CONFIG_FIELDS + 1)})
    with pytest.raises(ValidationError):
        FamilyHypothesis(fields={"key": "v" * 600})


def test_escalation_options_are_bounded():
    Escalation(question="which?", options=["a", "b", "c", "d"])  # 4 is the max
    with pytest.raises(ValidationError):
        Escalation(question="which?", options=["a", "b", "c", "d", "e"])
    with pytest.raises(ValidationError):
        Escalation(question="which?", options=["x" * 3000])


# ---------------------------------------------------------------- plan

def test_plan_agent_names_are_normalized_and_deduped():
    p = Plan(agents=["  Correlator", "correlator", "NOVELTY_DETECTOR", "", "ioc_extractor"])
    assert p.agents == ["correlator", "novelty_detector", "ioc_extractor"]


def test_plan_budget_bounds():
    assert Plan(budget_tokens=0).budget_tokens == 0
    with pytest.raises(ValidationError):
        Plan(budget_tokens=-1)
    with pytest.raises(ValidationError):
        Plan(budget_tokens=10_000_000)


# ---------------------------------------------------------------- priors (input posture)

def test_priors_tolerate_spine_extras_and_truncate():
    # Priors ARRIVE from the Go spine too, which sends a 'tier' field and may grow
    # more: extras must never 422 the enrichment, and an over-long list is
    # truncated (bounded acceptance), not rejected.
    p = Prior.model_validate(
        {"kind": "attck", "key": "T1055", "relation": "known-technique",
         "confidence": "HIGH", "fact_id": "kf_1", "tier": "L0", "some_future_field": 1}
    )
    assert p.tier == "L0" and p.fact_id == "kf_1"
    many = Priors(priors=[Prior(kind="attck", key=f"T{i}") for i in range(MAX_PRIORS + 10)])
    assert len(many.priors) == MAX_PRIORS
