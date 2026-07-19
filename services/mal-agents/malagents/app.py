"""The HTTP surface the Go orchestrator's enrichment activity calls.

Deliberately thin: it validates the incoming Evidence against the shared contract,
runs an agent, and returns the typed Proposal. The Go side re-validates and gates
everything this returns - this service is the untrusted reasoning muscle, not a
trusted component. It binds to loopback in the jailed container; the broker /
activity boundary is the containment, exactly like the capa and floss workers.
"""

from __future__ import annotations

from fastapi import FastAPI

from .agents.analyst import analyze
from .models import Evidence, Proposal
from .provider import model_configured

app = FastAPI(title="OpenMalLab agent plane", version="0.1.0")


@app.get("/healthz")
def healthz() -> dict:
    """Liveness + whether a live model is configured (else the test model is used)."""
    return {"ok": True, "model_configured": model_configured()}


@app.post("/v1/analyze", response_model=Proposal)
async def v1_analyze(evidence: Evidence) -> Proposal:
    """Run the analyst agent over one submission's evidence and return a proposal."""
    return await analyze(evidence)
