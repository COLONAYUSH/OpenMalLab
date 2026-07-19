"""Shared construction for the roster agents.

Every agent is built the same way so the whole roster carries one robustness
posture, learned from running against a real model:

- ``temperature=0``: analysis must be reproducible. A deterministic decode also
  means a retry (which carries the validation error back to the model) changes the
  output because the CONTEXT changed, not because of sampling noise.
- ``retries=3``: a real model occasionally emits output that misses the schema
  (wrong field name, a missing required field). pydantic-ai feeds the validation
  error back and lets the model self-correct; one retry proved too tight under
  load, so give it room rather than fail the whole enrichment. The Go side still
  re-validates and gates everything, so a few extra attempts cost latency, never
  trust.
"""

from __future__ import annotations

from pydantic_ai import Agent
from pydantic_ai.settings import ModelSettings

from ..provider import get_model

AGENT_RETRIES = 3


def make_agent(output_type, system_prompt: str) -> Agent:
    """Build a roster agent over the configured model (TestModel offline) with the
    shared deterministic + retry posture."""
    return Agent(
        get_model(),
        output_type=output_type,
        system_prompt=system_prompt,
        retries=AGENT_RETRIES,
        model_settings=ModelSettings(temperature=0),
    )
