from __future__ import annotations

import asyncio

import pytest

import watchdog_research.openclaw_sensors as sensor_module
from watchdog_research.domain import ThreatDomain
from watchdog_research.openclaw_sensors import OpenClawSensor

from .openclaw_fakes import FakeExecuteResult, FakeOpenClawClient


def test_openclaw_sensor_collects_and_clamps_signals(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeOpenClawClient.prime(
        [
            FakeExecuteResult(
                success=True,
                content="""
```json
[
  {"severity": 1.2, "confidence": 0.7, "summary": "Known exploit chain observed"},
  {"severity": 0.4, "confidence": -0.1, "summary": "Credential stuffing chatter"}
]
```
                """,
            ),
        ],
    )
    monkeypatch.setattr(sensor_module, "load_openclaw_client", lambda: FakeOpenClawClient)

    sensor = OpenClawSensor(
        name="cyber-osint",
        domain=ThreatDomain.CYBER,
        gateway_url="ws://test-gateway",
        agent_id="sensor-agent",
        search_queries=["critical CVE today"],
        urls_to_monitor=["https://example.com/feed"],
        openrouter_model="openrouter/test-model",
    )
    signals = sensor.collect(tick=3)

    assert len(signals) == 2
    assert signals[0].severity == 1.0
    assert signals[1].confidence == 0.0
    assert signals[0].metadata["mode"] == "openclaw"
    assert signals[0].metadata["tick"] == 3
    assert FakeOpenClawClient.gateway_urls == ["ws://test-gateway"]
    assert FakeOpenClawClient.agent_ids == ["sensor-agent"]
    prompt = FakeOpenClawClient.recorded_prompts()[0]
    assert "critical CVE today" in prompt
    assert "openrouter/test-model" in prompt


def test_openclaw_sensor_returns_empty_for_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeOpenClawClient.prime([FakeExecuteResult(success=False, content="offline")])
    monkeypatch.setattr(sensor_module, "load_openclaw_client", lambda: FakeOpenClawClient)

    sensor = OpenClawSensor(name="cyber-osint", domain=ThreatDomain.CYBER)
    assert sensor.collect(tick=1) == []


def test_openclaw_sensor_returns_empty_for_invalid_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeOpenClawClient.prime([FakeExecuteResult(success=True, content="not-json")])
    monkeypatch.setattr(sensor_module, "load_openclaw_client", lambda: FakeOpenClawClient)

    sensor = OpenClawSensor(name="cyber-osint", domain=ThreatDomain.CYBER)
    assert sensor.collect(tick=2) == []


def test_openclaw_sensor_sync_api_rejects_running_event_loop() -> None:
    async def _inner() -> None:
        sensor = OpenClawSensor(name="cyber-osint", domain=ThreatDomain.CYBER)
        with pytest.raises(RuntimeError, match="async API variant"):
            sensor.collect(tick=1)

    asyncio.run(_inner())
