"""Model provider for the agent roster.

One switch: a local, OpenAI-compatible vLLM server when ``MAL_MODEL_URL`` is set,
otherwise a deterministic in-process test model so the whole service runs and is
testable fully offline (the air-gapped default). This mirrors the Go provider's
local-default / loopback posture: the sovereign promise depends only on the local
path; the Go ``NewLocalProvider`` enforces loopback, and egress stays off unless a
deployment explicitly opts in.
"""

from __future__ import annotations

import os


def model_configured() -> bool:
    """True if a live model endpoint is configured (else the test model is used)."""
    return bool(os.environ.get("MAL_MODEL_URL", "").strip())


def get_model():
    """Return a pydantic-ai model.

    - ``MAL_MODEL_URL`` set -> an OpenAI-compatible client to the local vLLM server
      (``MAL_MODEL_NAME`` names the served model). The API key is irrelevant for a
      local server but the client wants a non-empty value.
    - unset -> ``TestModel``: deterministic, in-process, no network. The service is
      fully exercisable offline and in CI with this.
    """
    url = os.environ.get("MAL_MODEL_URL", "").strip()
    if not url:
        from pydantic_ai.models.test import TestModel

        return TestModel()

    from pydantic_ai.models.openai import OpenAIModel
    from pydantic_ai.providers.openai import OpenAIProvider

    name = os.environ.get("MAL_MODEL_NAME", "local")
    base = url.rstrip("/")
    if not base.endswith("/v1"):
        base += "/v1"
    return OpenAIModel(
        name,
        provider=OpenAIProvider(base_url=base, api_key=os.environ.get("MAL_MODEL_KEY", "sk-local")),
    )
