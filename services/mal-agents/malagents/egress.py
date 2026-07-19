"""Egress minimization for the opt-in cloud model path.

When (and only when) a deployment opts into a remote model, evidence leaves the
box. This strips the projection to the analytical signal a model needs to reason -
engine, type, ATT&CK id, verdict, capped free text - and drops the bits that need
not egress: the file hash and any filesystem paths (which can leak usernames or org
structure). The loopback (sovereign) path is NEVER minimized: locally, the model
gets the full projection. Applied once at the HTTP boundary, before any agent runs.
"""

from __future__ import annotations

from .models import Evidence, EvidenceItem

MAX_DETAIL_EGRESS = 512  # cap free-text detail that crosses the wire


def minimize_for_egress(ev: Evidence) -> Evidence:
    """Return a copy of the evidence reduced to what may safely leave the box."""
    items = [
        EvidenceItem(
            engine=it.engine,
            type=it.type,
            detail=it.detail[:MAX_DETAIL_EGRESS],
            attck=it.attck,
            verdict=it.verdict,
            confidence=it.confidence,
            path="",  # filesystem paths never egress
        )
        for it in ev.items
    ]
    # drop the file hash (identifying); keep the deterministic verdict/score signal.
    return ev.model_copy(update={"items": items, "sha256": ""})
