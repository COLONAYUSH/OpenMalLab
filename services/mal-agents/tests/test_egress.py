"""Egress minimization: only the analytical signal may leave the box."""

from malagents.egress import MAX_DETAIL_EGRESS, minimize_for_egress
from malagents.models import Evidence, EvidenceItem


def test_minimize_drops_hash_and_paths_keeps_signal():
    ev = Evidence(
        submission_id="s",
        sha256="a" * 64,
        file_type="PE32",
        verdict="SUSPICIOUS",
        score=61,
        confidence="MEDIUM",
        items=[
            EvidenceItem(
                engine="mal-capa",
                type="capability",
                attck="T1055",
                detail="inject into a remote process",
                verdict="SUSPICIOUS",
                path="/home/alice/samples/x.bin",
            )
        ],
    )
    out = minimize_for_egress(ev)

    # identifying / sensitive bits are dropped before egress
    assert out.sha256 == ""
    assert out.items[0].path == ""

    # the analytical signal is preserved so the model can still reason
    it = out.items[0]
    assert (it.engine, it.type, it.attck, it.verdict) == ("mal-capa", "capability", "T1055", "SUSPICIOUS")
    assert out.verdict == "SUSPICIOUS" and out.score == 61

    # the original evidence is untouched (minimization returns a copy)
    assert ev.sha256 == "a" * 64
    assert ev.items[0].path.endswith("x.bin")


def test_minimize_caps_free_text_detail():
    big = "A" * (MAX_DETAIL_EGRESS + 500)
    ev = Evidence(items=[EvidenceItem(engine="e", detail=big)])
    out = minimize_for_egress(ev)
    assert len(out.items[0].detail) == MAX_DETAIL_EGRESS
