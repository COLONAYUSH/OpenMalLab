"""Optional Langfuse observability (design sec 10/11).

Every agent run can be traced to a self-hosted Langfuse instance for on-premise
evals and audit - but only when configured. With no MAL_LANGFUSE_* environment,
tracing is a no-op, so the air-gapped default emits no telemetry and pulls in no
runtime dependency (langfuse is imported lazily). The tracer is a thin context
manager the agents wrap their run in, and it NEVER raises into the agent path:
observability must not be able to break analysis, so any tracing error is
swallowed and the run proceeds untraced.
"""

from __future__ import annotations

import contextlib
import os
from typing import Iterator


def enabled() -> bool:
    """True only when a Langfuse host and public key are configured."""
    return bool(
        os.environ.get("MAL_LANGFUSE_URL", "").strip()
        and os.environ.get("MAL_LANGFUSE_PUBLIC_KEY", "").strip()
    )


@contextlib.contextmanager
def trace(name: str, **metadata) -> Iterator[None]:
    """Trace one agent run. A no-op unless Langfuse is configured; any tracing or
    import error is swallowed so the analysis path is never affected."""
    if not enabled():
        yield
        return

    client = None
    span = None
    try:
        from langfuse import Langfuse  # lazy: not a hard dependency of the service

        client = Langfuse(
            host=os.environ["MAL_LANGFUSE_URL"],
            public_key=os.environ["MAL_LANGFUSE_PUBLIC_KEY"],
            secret_key=os.environ.get("MAL_LANGFUSE_SECRET_KEY", ""),
        )
        span = client.trace(name=name, metadata=metadata)
    except Exception:
        # langfuse missing, misconfigured, or unreachable: proceed untraced.
        yield
        return

    try:
        yield
    finally:
        try:
            if span is not None:
                span.update(output="completed")
            if client is not None:
                client.flush()
        except Exception:
            pass
