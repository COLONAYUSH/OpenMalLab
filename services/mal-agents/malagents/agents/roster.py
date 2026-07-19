"""The roster registry + dispatcher.

Maps agent names to their typed run functions so the Temporal agent-graph and the
HTTP surface can spawn agents by name (the Router names which to spawn). Each
agent keeps its own typed signature; run_agent adapts the shared call, passing
only the context each agent consumes, and fails closed on an unknown name.
"""

from __future__ import annotations

from . import (
    analyst,
    capability_reasoner,
    correlator,
    escalation,
    family_hypothesizer,
    ioc_extractor,
    novelty_detector,
    report_writer,
    router,
    verifier,
)

# the spawnable roster. analyst is the aggregate P0 agent, kept callable too.
ROSTER = (
    "router",
    "correlator",
    "capability_reasoner",
    "ioc_extractor",
    "family_hypothesizer",
    "novelty_detector",
    "verifier",
    "report_writer",
    "escalation",
    "analyst",
)


async def run_agent(name, ev, *, priors=None, claim="", reason="", confirmed=None):
    """Dispatch to a roster agent by name, passing only the context it consumes.

    Raises ValueError on an unknown name (fail-closed). The Temporal graph calls
    this via the HTTP surface; each agent's own typed output is returned.
    """
    if name == "router":
        return await router.run(ev)
    if name == "correlator":
        return await correlator.run(ev)
    if name == "capability_reasoner":
        return await capability_reasoner.run(ev, priors)
    if name == "ioc_extractor":
        return await ioc_extractor.run(ev)
    if name == "family_hypothesizer":
        return await family_hypothesizer.run(ev, priors)
    if name == "novelty_detector":
        return await novelty_detector.run(ev)
    if name == "verifier":
        return await verifier.run(ev, claim)
    if name == "report_writer":
        return await report_writer.run(ev, confirmed)
    if name == "escalation":
        return await escalation.run(ev, reason)
    if name == "analyst":
        return await analyst.analyze(ev)
    raise ValueError("unknown agent: %s" % name)
