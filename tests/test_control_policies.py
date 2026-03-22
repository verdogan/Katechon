from __future__ import annotations

import pytest

import watchdog_research.openclaw_utils as openclaw_utils
from watchdog_research.config import ResearchConfig
from watchdog_research.control_policies import (
    AdaptiveThreshold,
    ConstitutionalCheck,
    MultiAgentDebate,
    ThresholdGating,
    build_policy,
)
from watchdog_research.domain import (
    ActionKind,
    ExecutionResult,
    ExecutionStatus,
    InterventionPlan,
    MissionOutcome,
    PlannedAction,
    ThreatDomain,
    ThreatSignal,
    VerificationResult,
    WorldState,
)
from watchdog_research.loop import WatchdogResearchLoop

from .conftest import FixedProvider
from .openclaw_fakes import FakeExecuteResult, FakeOpenClawClient


def _make_plan(
    priority: float = 0.8,
    domain: ThreatDomain = ThreatDomain.CYBER,
    n_actions: int = 2,
    counterfactual: float = 0.5,
) -> InterventionPlan:
    actions = [
        PlannedAction(kind=ActionKind.TRIAGE, description="test", target="soc")
        for _ in range(n_actions)
    ]
    return InterventionPlan(
        objective="test plan",
        priority=priority,
        rationale="testing",
        actions=actions,
        requires_human_review=priority >= 0.72,
        primary_domain=domain,
        counterfactual_score=counterfactual,
    )


def _make_state(
    risk_index: float = 0.5,
    threats: list[ThreatSignal] | None = None,
) -> WorldState:
    state = WorldState()
    signals = threats or [
        ThreatSignal("src", ThreatDomain.CYBER, 0.7, 0.8, "test signal"),
    ]
    state.ingest(signals)
    state.risk_index = risk_index
    return state


def _make_verification(outcome: MissionOutcome) -> VerificationResult:
    return VerificationResult(
        success_probability=0.7,
        outcome=outcome,
        recommended_adjustment="stabilize_and_monitor",
        notes="test",
    )


def _make_result(status: ExecutionStatus = ExecutionStatus.SIMULATED) -> ExecutionResult:
    return ExecutionResult(
        plan_id="test",
        status=status,
        action_log=["test"],
        estimated_impact=0.6,
        side_effect_risk=0.2,
    )


class TestThresholdGating:
    def test_allows_below_threshold(self) -> None:
        policy = ThresholdGating(threshold=0.72)
        plan = _make_plan(priority=0.5)
        assert policy.should_allow(plan, _make_state()) is True

    def test_blocks_above_threshold(self) -> None:
        policy = ThresholdGating(threshold=0.72)
        plan = _make_plan(priority=0.85)
        assert policy.should_allow(plan, _make_state()) is False

    def test_blocks_at_threshold(self) -> None:
        policy = ThresholdGating(threshold=0.72)
        plan = _make_plan(priority=0.72)
        assert policy.should_allow(plan, _make_state()) is False

    def test_name_includes_threshold(self) -> None:
        policy = ThresholdGating(threshold=0.80)
        assert "0.80" in policy.name


class TestAdaptiveThreshold:
    def test_lowers_threshold_after_stabilization(self) -> None:
        policy = AdaptiveThreshold(initial_threshold=0.72)
        plan = _make_plan(priority=0.5)
        result = _make_result()
        verification = _make_verification(MissionOutcome.STABILIZED)

        initial = policy._current_threshold
        policy.notify_outcome(plan, result, verification)
        assert policy._current_threshold < initial

    def test_raises_threshold_after_failure(self) -> None:
        policy = AdaptiveThreshold(initial_threshold=0.72)
        plan = _make_plan(priority=0.5)
        result = _make_result()
        verification = _make_verification(MissionOutcome.INEFFECTIVE)

        initial = policy._current_threshold
        policy.notify_outcome(plan, result, verification)
        assert policy._current_threshold > initial

    def test_respects_min_threshold(self) -> None:
        policy = AdaptiveThreshold(
            initial_threshold=0.52, min_threshold=0.50, success_adjustment=-0.04,
        )
        plan = _make_plan()
        result = _make_result()
        verification = _make_verification(MissionOutcome.STABILIZED)

        policy.notify_outcome(plan, result, verification)
        assert policy._current_threshold >= policy.min_threshold

    def test_respects_max_threshold(self) -> None:
        policy = AdaptiveThreshold(
            initial_threshold=0.93, max_threshold=0.95, failure_adjustment=0.06,
        )
        plan = _make_plan()
        result = _make_result()
        verification = _make_verification(MissionOutcome.INEFFECTIVE)

        policy.notify_outcome(plan, result, verification)
        assert policy._current_threshold <= policy.max_threshold

    def test_reset_restores_initial(self) -> None:
        policy = AdaptiveThreshold(initial_threshold=0.72)
        plan = _make_plan()
        result = _make_result()
        verification = _make_verification(MissionOutcome.STABILIZED)

        policy.notify_outcome(plan, result, verification)
        assert policy._current_threshold != 0.72

        policy.reset()
        assert policy._current_threshold == 0.72


class TestConstitutionalCheck:
    def test_blocks_when_too_many_domains(self) -> None:
        policy = ConstitutionalCheck(max_concurrent_domains=1)
        state = _make_state(threats=[
            ThreatSignal("a", ThreatDomain.CYBER, 0.7, 0.8, "t1"),
            ThreatSignal("b", ThreatDomain.INFRA, 0.6, 0.7, "t2"),
        ])
        plan = _make_plan(priority=0.5)
        assert policy.should_allow(plan, state) is False

    def test_allows_high_priority_despite_many_domains(self) -> None:
        policy = ConstitutionalCheck(max_concurrent_domains=1)
        state = _make_state(threats=[
            ThreatSignal("a", ThreatDomain.CYBER, 0.7, 0.8, "t1"),
            ThreatSignal("b", ThreatDomain.INFRA, 0.6, 0.7, "t2"),
        ])
        plan = _make_plan(priority=0.90)
        assert policy.should_allow(plan, state) is True

    def test_blocks_too_many_actions(self) -> None:
        policy = ConstitutionalCheck(max_actions_per_plan=2)
        plan = _make_plan(n_actions=3)
        assert policy.should_allow(plan, _make_state()) is False

    def test_blocks_low_confidence_signals(self) -> None:
        policy = ConstitutionalCheck(min_confidence_for_action=0.60)
        state = _make_state(threats=[
            ThreatSignal("a", ThreatDomain.CYBER, 0.7, 0.3, "low conf"),
        ])
        plan = _make_plan(priority=0.5, domain=ThreatDomain.CYBER)
        assert policy.should_allow(plan, state) is False

    def test_allows_when_all_rules_pass(self) -> None:
        policy = ConstitutionalCheck()
        plan = _make_plan(priority=0.5, n_actions=2)
        assert policy.should_allow(plan, _make_state()) is True


class TestMultiAgentDebate:
    def test_heuristic_mode_returns_bool(self) -> None:
        policy = MultiAgentDebate(use_openclaw=False, seed=42)
        plan = _make_plan(priority=0.5, counterfactual=0.6)
        result = policy.should_allow(plan, _make_state())
        assert isinstance(result, bool)

    def test_deterministic_with_same_seed(self) -> None:
        results = []
        for _ in range(3):
            policy = MultiAgentDebate(use_openclaw=False, seed=42)
            plan = _make_plan(priority=0.6, counterfactual=0.5)
            results.append(policy.should_allow(plan, _make_state(risk_index=0.4)))
        assert len(set(results)) == 1

    def test_name_reflects_mode(self) -> None:
        assert "heuristic" in MultiAgentDebate(use_openclaw=False).name
        assert "llm" in MultiAgentDebate(use_openclaw=True).name

    def test_llm_mode_uses_openclaw_scores(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        FakeOpenClawClient.prime(
            [
                FakeExecuteResult(success=True, content='{"score": 0.9, "argument": "act"}'),
                FakeExecuteResult(success=True, content='{"score": 0.7, "argument": "caution"}'),
            ]
        )
        monkeypatch.setattr(
            openclaw_utils,
            "load_openclaw_client",
            lambda: FakeOpenClawClient,
        )

        policy = MultiAgentDebate(
            use_openclaw=True,
            agent_id="debate-agent",
            gateway_url="ws://test-gateway",
            openrouter_model="openrouter/test-model",
        )

        allowed = policy.should_allow(
            _make_plan(priority=0.6, counterfactual=0.7),
            _make_state(risk_index=0.4),
        )

        assert allowed is True
        assert FakeOpenClawClient.gateway_urls == ["ws://test-gateway"]
        assert FakeOpenClawClient.agent_ids == ["debate-agent"]
        prompts = FakeOpenClawClient.recorded_prompts()
        assert len(prompts) == 2
        assert "Argue FOR execution" in prompts[0]
        assert "Argue AGAINST execution" in prompts[1]

    def test_llm_mode_raises_when_openclaw_fails(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        FakeOpenClawClient.prime(
            [FakeExecuteResult(success=False, content="gateway timeout")]
        )
        monkeypatch.setattr(
            openclaw_utils,
            "load_openclaw_client",
            lambda: FakeOpenClawClient,
        )

        policy = MultiAgentDebate(use_openclaw=True)
        with pytest.raises(RuntimeError, match="refusing to fall back"):
            policy.should_allow(_make_plan(priority=0.6), _make_state(risk_index=0.4))

    def test_llm_mode_raises_on_invalid_json_response(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        FakeOpenClawClient.prime(
            [
                FakeExecuteResult(success=True, content="not-json"),
                FakeExecuteResult(success=True, content='{"score": 0.2, "argument": "hold"}'),
            ]
        )
        monkeypatch.setattr(
            openclaw_utils,
            "load_openclaw_client",
            lambda: FakeOpenClawClient,
        )

        policy = MultiAgentDebate(use_openclaw=True)
        with pytest.raises(RuntimeError, match="refusing to fall back"):
            policy.should_allow(_make_plan(priority=0.6), _make_state(risk_index=0.4))


class TestBuildPolicy:
    def test_builds_known_policies(self) -> None:
        for name in ("threshold", "adaptive", "constitutional", "debate"):
            policy = build_policy(name)
            assert hasattr(policy, "should_allow")

    def test_raises_for_unknown_policy(self) -> None:
        with pytest.raises(ValueError, match="Unknown policy"):
            build_policy("nonexistent")

    def test_passes_kwargs(self) -> None:
        policy = build_policy("threshold", threshold=0.99)
        assert policy.threshold == 0.99  # type: ignore[union-attr]


class TestLoopWithPolicy:
    def test_loop_uses_injected_policy(self) -> None:
        provider = FixedProvider(severity=0.95, confidence=0.95, domain=ThreatDomain.CYBER)
        policy = ThresholdGating(threshold=1.01)
        loop = WatchdogResearchLoop(
            providers=[provider], config=ResearchConfig(), seed=5, policy=policy,
        )
        record = loop.run_step(approved=False)

        assert record.result is not None
        assert record.result.status is ExecutionStatus.SIMULATED
        assert record.policy_name == policy.name

    def test_constitutional_blocks_in_loop(self) -> None:
        providers = [
            FixedProvider(severity=0.7, confidence=0.3, domain=ThreatDomain.CYBER),
        ]
        policy = ConstitutionalCheck(min_confidence_for_action=0.50)
        loop = WatchdogResearchLoop(
            providers=providers, config=ResearchConfig(), seed=5, policy=policy,
        )
        record = loop.run_step(approved=False)

        assert record.result is not None
        assert record.result.status is ExecutionStatus.BLOCKED_REVIEW

    def test_approved_overrides_policy(self) -> None:
        provider = FixedProvider(severity=0.95, confidence=0.95, domain=ThreatDomain.CYBER)
        policy = ThresholdGating(threshold=0.50)
        loop = WatchdogResearchLoop(
            providers=[provider], config=ResearchConfig(), seed=5, policy=policy,
        )
        record = loop.run_step(approved=True)

        assert record.result is not None
        assert record.result.status is ExecutionStatus.SIMULATED
