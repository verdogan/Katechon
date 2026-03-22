from __future__ import annotations

from typing import Any

from .domain import ThreatDomain, ThreatSignal
from .openclaw_utils import (
    DEFAULT_GATEWAY_URL,
    DEFAULT_OPENROUTER_MODEL,
    clamp01,
    connect_openclaw_client,
    load_openclaw_client,
    parse_json_array,
    run_coro_sync,
)

DEFAULT_AGENT_ID = "watchdog-sensor"


class OpenClawSensor:
    """Signal provider that gathers threat indicators through OpenClaw."""

    def __init__(
        self,
        name: str,
        domain: ThreatDomain,
        agent_id: str = DEFAULT_AGENT_ID,
        gateway_url: str = DEFAULT_GATEWAY_URL,
        search_queries: list[str] | None = None,
        urls_to_monitor: list[str] | None = None,
        openrouter_model: str = DEFAULT_OPENROUTER_MODEL,
    ) -> None:
        self.name = name
        self._domain = domain
        self._agent_id = agent_id
        self._gateway_url = gateway_url
        self._search_queries = search_queries or []
        self._urls_to_monitor = urls_to_monitor or []
        self._openrouter_model = openrouter_model

    def collect(self, tick: int) -> list[ThreatSignal]:
        return run_coro_sync(
            self.acollect(tick),
            api_name="OpenClawSensor.collect",
        )

    async def acollect(self, tick: int) -> list[ThreatSignal]:
        client_cls = load_openclaw_client()
        client_ctx = await connect_openclaw_client(client_cls, self._gateway_url)
        async with client_ctx as client:
            agent = client.get_agent(self._agent_id)
            result = await agent.execute(self._build_prompt())

        if not bool(getattr(result, "success", False)):
            return []

        content = getattr(result, "content", "")
        if not isinstance(content, str):
            return []
        return self._parse_signals(content, tick=tick)

    def _build_prompt(self) -> str:
        sections: list[str] = []
        if self._search_queries:
            queries = "\n".join(f"  - {query}" for query in self._search_queries)
            sections.append(f"Search queries:\n{queries}")
        if self._urls_to_monitor:
            urls = "\n".join(f"  - {url}" for url in self._urls_to_monitor)
            sections.append(f"URLs to inspect:\n{urls}")

        source_context = (
            "\n\n".join(sections)
            if sections
            else "Use current web intelligence sources."
        )

        return (
            f"Model preference: {self._openrouter_model} (via OpenRouter).\n\n"
            f"You are a threat intelligence sensor for the {self._domain.value} domain.\n"
            "Collect actionable indicators and estimate severity.\n\n"
            f"{source_context}\n\n"
            "Return ONLY a JSON array where each item has:\n"
            "  severity (0..1), confidence (0..1), summary (string).\n"
            "Return [] when no notable threats are found."
        )

    def _parse_signals(self, content: str, tick: int) -> list[ThreatSignal]:
        items = parse_json_array(content)
        if items is None:
            return []

        signals: list[ThreatSignal] = []
        for item in items:
            if not isinstance(item, dict):
                continue

            severity = clamp01(_coerce_float(item.get("severity"), default=0.5))
            confidence = clamp01(_coerce_float(item.get("confidence"), default=0.5))
            summary = _coerce_summary(item.get("summary"))

            signals.append(
                ThreatSignal(
                    source=self.name,
                    domain=self._domain,
                    severity=severity,
                    confidence=confidence,
                    summary=summary,
                    metadata={
                        "tick": tick,
                        "provider": self.name,
                        "mode": "openclaw",
                    },
                ),
            )
        return signals


def _coerce_float(value: Any, default: float) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return default
    return default


def _coerce_summary(value: Any) -> str:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return "OpenClaw sensor reported elevated activity."
