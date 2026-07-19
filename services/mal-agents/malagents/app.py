"""The HTTP surface the Go orchestrator's enrichment activity calls.

Deliberately thin: it validates the incoming Evidence against the shared contract,
runs an agent, and returns the typed Proposal. The Go side re-validates and gates
everything this returns - this service is the untrusted reasoning muscle, not a
trusted component. It binds to loopback in the jailed container; the broker /
activity boundary is the containment, exactly like the capa and floss workers.
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .agents.analyst import analyze
from .agents.roster import ROSTER, run_agent
from .agents.schemas import Priors
from .egress import minimize_for_egress
from .models import Evidence, Proposal
from .provider import cloud_enabled, model_configured

app = FastAPI(title="OpenMalLab agent plane", version="0.1.0")


def _for_model(ev: Evidence) -> Evidence:
    """Minimize evidence before it reaches the model IFF the cloud path is opted
    into; the local (sovereign) path gets the full projection unchanged."""
    return minimize_for_egress(ev) if cloud_enabled() else ev


@app.get("/healthz")
def healthz() -> dict:
    """Liveness + whether a live model is configured (else the test model is used)."""
    return {"ok": True, "model_configured": model_configured(), "cloud_egress": cloud_enabled()}


@app.get("/v1/roster")
def v1_roster() -> dict:
    """The spawnable agent names (the Router picks from these)."""
    return {"agents": list(ROSTER)}


@app.post("/v1/analyze", response_model=Proposal)
async def v1_analyze(evidence: Evidence) -> Proposal:
    """Run the analyst agent over one submission's evidence and return a proposal."""
    return await analyze(_for_model(evidence))


class AgentRequest(BaseModel):
    """Call one roster agent by name. Only the fields an agent consumes are used;
    the rest are ignored, so the Temporal graph sends a uniform envelope."""

    evidence: Evidence
    priors: Priors | None = None
    claim: str = ""
    reason: str = ""
    confirmed: list[str] = Field(default_factory=list)


@app.post("/v1/agent/{name}")
async def v1_agent(name: str, req: AgentRequest):
    """Dispatch to a single roster agent. 404 on an unknown name (fail-closed).
    Returns that agent's own typed output; the Go side re-validates and gates it."""
    if name not in ROSTER:
        raise HTTPException(status_code=404, detail="unknown agent")
    return await run_agent(
        name,
        _for_model(req.evidence),
        priors=req.priors,
        claim=req.claim,
        reason=req.reason,
        confirmed=req.confirmed,
    )
