from __future__ import annotations

import asyncio

import pytest

import watchdog_research.openclaw_planner as planner_module
from watchdog_research.config import ResearchConfig
from watchdog_research.domain import ActionKind, ThreatDomain, ThreatSignal, WorldState
from watchdog_research.openclaw_planner import OpenClawPlanner

from .openclaw_fakes import FakeExecuteResult, FakeOpenClawClient


def _state_with_signal() -> WorldState:
    state = WorldState()
    state.ingest(
        [
            ThreatSignal(
                source="cyber-feed",
                domain=ThreatDomain.CYBER,
                severity=0.9,
                confidence=0.8,
                summary="high-confidence cyber escalation",
            ),
        ],
    )
    return state


def test_openclaw_planner_parses_and_limits_actions(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeOpenClawClient.prime(
        [
            FakeExecuteResult(
                success=True,
                content="""
```json
{
  "objective": "Stabilize cyber risk",
  "domain": "cyber",
  "priority": 0.86,
  "rationale": "High severity with elevated confidence.",
  "counterfactual_estimate": 0.73,
  "requires_human_review": true,
  "actions": [
    {"kind": "triage", "description": "Correlate indicators", "target": "soc"},
    {"kind": "contain", "description": "Segment impacted nodes", "target": "network"},
    {"kind": "monitor", "description": "Increase telemetry", "target": "observability"}
  ]
}
```
                """,
            ),
        ],
    )
    monkeypatch.setattr(planner_module, "load_openclaw_client", lambda: FakeOpenClawClient)

    planner = OpenClawPlanner(
        config=ResearchConfig(max_actions_per_plan=2, review_threshold=0.75),
        agent_id="planner-agent",
        gateway_url="ws://test-gateway",
        openrouter_model="openrouter/test-model",
    )

    plan = planner.create_plan(_state_with_signal())
    assert plan is not None
    assert plan.priority == 0.86
    assert plan.requires_human_review is True
    assert plan.counterfactual_score == 0.73
    assert len(plan.actions) == 2
    assert plan.actions[0].kind is ActionKind.TRIAGE
    assert plan.actions[1].kind is ActionKind.CONTAIN
    assert FakeOpenClawClient.gateway_urls == ["ws://test-gateway"]
    assert FakeOpenClawClient.agent_ids == ["planner-agent"]
    assert "openrouter/test-model" in FakeOpenClawClient.recorded_prompts()[0]


def test_openclaw_planner_returns_none_when_agent_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeOpenClawClient.prime([FakeExecuteResult(success=False, content="gateway timeout")])
    monkeypatch.setattr(planner_module, "load_openclaw_client", lambda: FakeOpenClawClient)

    planner = OpenClawPlanner(config=ResearchConfig())
    plan = planner.create_plan(_state_with_signal())

    assert plan is None


def test_openclaw_planner_create_candidates_wraps_plan(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeOpenClawClient.prime(
        [
            FakeExecuteResult(
                success=True,
                content=(
                    '{"objective":"obj","domain":"cyber","priority":0.55,'
                    '"rationale":"r","counterfactual_estimate":0.5,'
                    '"requires_human_review":false,'
                    '"actions":[{"kind":"triage","description":"d","target":"soc"}]}'
                ),
            ),
        ],
    )
    monkeypatch.setattr(planner_module, "load_openclaw_client", lambda: FakeOpenClawClient)

    planner = OpenClawPlanner(config=ResearchConfig())
    candidates = planner.create_candidates(_state_with_signal())

    assert len(candidates) == 1
    assert candidates[0].objective == "obj"


def test_openclaw_planner_sync_api_rejects_running_event_loop() -> None:
    async def _inner() -> None:
        planner = OpenClawPlanner(config=ResearchConfig())
        with pytest.raises(RuntimeError, match="async API variant"):
            planner.create_plan(_state_with_signal())

    asyncio.run(_inner())
