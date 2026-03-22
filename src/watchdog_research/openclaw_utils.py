from __future__ import annotations

import asyncio
import importlib
import inspect
import json
import os
from collections.abc import Coroutine
from typing import Any, TypeVar

DEFAULT_GATEWAY_URL = "ws://127.0.0.1:18789/gateway"
DEFAULT_OPENROUTER_MODEL = "openai/gpt-5.4-nano"

_T = TypeVar("_T")


def clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))


def load_openclaw_client() -> Any:
    """Load OpenClawClient lazily so the package remains optional."""
    try:
        module = importlib.import_module("openclaw_sdk")
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "openclaw-sdk is required for OpenClaw integrations. "
            "Install it with: pip install openclaw-sdk"
        ) from exc

    client = getattr(module, "OpenClawClient", None)
    if client is None:
        raise RuntimeError("openclaw_sdk.OpenClawClient was not found.")
    return client


def strip_markdown_fences(content: str) -> str:
    cleaned = content.strip()
    if not cleaned.startswith("```"):
        return cleaned

    lines = cleaned.splitlines()
    if len(lines) < 2:
        return cleaned
    if not lines[-1].strip().startswith("```"):
        return cleaned
    return "\n".join(lines[1:-1]).strip()


def parse_json_object(content: str) -> dict[str, Any] | None:
    cleaned = strip_markdown_fences(content)

    parsed = _parse_json(cleaned)
    if isinstance(parsed, dict):
        return parsed

    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None

    parsed = _parse_json(cleaned[start : end + 1])
    if isinstance(parsed, dict):
        return parsed
    return None


def parse_json_array(content: str) -> list[Any] | None:
    cleaned = strip_markdown_fences(content)

    parsed = _parse_json(cleaned)
    if isinstance(parsed, list):
        return parsed

    start = cleaned.find("[")
    end = cleaned.rfind("]")
    if start == -1 or end == -1 or end <= start:
        return None

    parsed = _parse_json(cleaned[start : end + 1])
    if isinstance(parsed, list):
        return parsed
    return None


def _parse_json(raw: str) -> Any:
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def run_coro_sync(coro: Coroutine[Any, Any, _T], *, api_name: str) -> _T:
    """Run a coroutine from sync code when no loop is active.

    If a loop is already running (e.g., Jupyter, async web frameworks), callers
    should use the corresponding async API directly.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    coro.close()
    raise RuntimeError(
        f"{api_name}() cannot be used while an asyncio event loop is running. "
        f"Use the async API variant instead.",
    )


async def connect_openclaw_client(client_cls: Any, gateway_ws_url: str) -> Any:
    """Connect to OpenClaw across SDK connect() variants.

    Some SDK versions expose connect() as an awaitable coroutine that returns
    a client object; others may return the client directly.
    """
    connect_kwargs: dict[str, Any] = {"gateway_ws_url": gateway_ws_url}
    api_key = os.environ.get("OPENCLAW_API_KEY") or os.environ.get("OPENCLAW_GATEWAY_TOKEN")
    if api_key:
        connect_kwargs["api_key"] = api_key

    maybe_client = client_cls.connect(**connect_kwargs)
    if inspect.isawaitable(maybe_client):
        return await maybe_client
    return maybe_client
