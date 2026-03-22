from __future__ import annotations

import asyncio

import pytest

import watchdog_research.openclaw_effector as effector_module
from watchdog_research.config import ResearchConfig
from watchdog_research.domain import (
    ActionKind,
    ExecutionStatus,
    InterventionPlan,
    PlannedAction,
)
from watchdog_research.openclaw_effector import OpenClawEffector

from .openclaw_fakes import FakeExecuteResult, FakeOpenClawClient


def _plan(*, requires_review: bool = False, with_actions: bool = True) -> InterventionPlan:
    actions = (
        [
            PlannedAction(
                kind=ActionKind.TRIAGE,
                description="Correlate indicators",
                target="soc",
            ),
            PlannedAction(
                kind=ActionKind.CONTAIN,
                description="Segment suspicious hosts",
                target="network",
            ),
        ]
        if with_actions
        else []
    )
    return InterventionPlan(
        objective="Contain cyber escalation",
        priority=0.8,
        rationale="test",
        actions=actions,
        requires_human_review=requires_review,
        counterfactual_score=0.7,
    )


def test_openclaw_effector_blocks_when_unapproved() -> None:
    effector = OpenClawEffector(config=ResearchConfig())
    result = effector.execute(_plan(requires_review=True), approved=False)

    assert result.status is ExecutionStatus.BLOCKED_REVIEW
    assert result.estimated_impact == 0.0


def test_openclaw_effector_blocks_policy_denial_without_review_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeOpenClawClient.prime([FakeExecuteResult(success=True, content="should not run")])
    monkeypatch.setattr(effector_module, "load_openclaw_client", lambda: FakeOpenClawClient)

    effector = OpenClawEffector(config=ResearchConfig(), gateway_url="ws://test-gateway")
    result = effector.execute(_plan(requires_review=False), approved=False)

    assert result.status is ExecutionStatus.BLOCKED_REVIEW
    assert result.estimated_impact == 0.0
    assert FakeOpenClawClient.gateway_urls == []


def test_openclaw_effector_executes_and_tracks_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeOpenClawClient.prime(
        [
            FakeExecuteResult(success=True, content="ok"),
            FakeExecuteResult(success=False, content="rate limited"),
        ],
    )
    monkeypatch.setattr(effector_module, "load_openclaw_client", lambda: FakeOpenClawClient)

    effector = OpenClawEffector(
        config=ResearchConfig(),
        agent_id="executor-agent",
        gateway_url="ws://test-gateway",
        openrouter_model="openrouter/test-model",
    )
    result = effector.execute(_plan(), approved=True)

    assert result.status is ExecutionStatus.EXECUTED
    assert result.estimated_impact == 0.5
    assert len(result.action_log) == 2
    assert "failed" in result.action_log[1]
    assert FakeOpenClawClient.gateway_urls == ["ws://test-gateway"]
    assert FakeOpenClawClient.agent_ids == ["executor-agent"]
    assert "openrouter/test-model" in FakeOpenClawClient.recorded_prompts()[0]


def test_openclaw_effector_handles_empty_plan(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeOpenClawClient.prime([])
    monkeypatch.setattr(effector_module, "load_openclaw_client", lambda: FakeOpenClawClient)

    effector = OpenClawEffector(config=ResearchConfig())
    result = effector.execute(_plan(with_actions=False), approved=True)

    assert result.status is ExecutionStatus.SKIPPED
    assert result.estimated_impact == 0.0


def test_openclaw_effector_sync_api_rejects_running_event_loop() -> None:
    async def _inner() -> None:
        effector = OpenClawEffector(config=ResearchConfig())
        with pytest.raises(RuntimeError, match="async API variant"):
            effector.execute(_plan(), approved=True)

    asyncio.run(_inner())
