from __future__ import annotations

from watchdog_research.config import ResearchConfig
from watchdog_research.domain import (
    ActionKind,
    ExecutionResult,
    ExecutionStatus,
    InterventionPlan,
    MissionOutcome,
    PlannedAction,
    ThreatDomain,
    WorldState,
)
from watchdog_research.effectors import SimulationEffector
from watchdog_research.loop import WatchdogResearchLoop

from .conftest import EmptyProvider, FixedProvider


class TestHighPriorityReview:
    def test_blocked_without_approval(self, strict_review_config: ResearchConfig) -> None:
        provider = FixedProvider(severity=0.95, confidence=0.95, domain=ThreatDomain.CYBER)
        loop = WatchdogResearchLoop(
            providers=[provider], config=strict_review_config, seed=5,
        )

        record = loop.run_step(approved=False)

        assert record.plan is not None
        assert record.plan.requires_human_review is True
        assert record.result is not None
        assert record.result.status is ExecutionStatus.BLOCKED_REVIEW
        assert record.verification is not None
        assert record.verification.outcome is MissionOutcome.BLOCKED

    def test_executes_when_approved(self, strict_review_config: ResearchConfig) -> None:
        provider = FixedProvider(severity=0.95, confidence=0.95, domain=ThreatDomain.INFRA)
        loop = WatchdogResearchLoop(
            providers=[provider], config=strict_review_config, seed=9,
        )

        record = loop.run_step(approved=True)

        assert record.result is not None
        assert record.result.status is ExecutionStatus.SIMULATED
        assert 0.0 <= record.result.estimated_impact <= 1.0


class TestRunMultipleSteps:
    def test_returns_correct_step_count(self) -> None:
        provider = FixedProvider(severity=0.5, confidence=0.7, domain=ThreatDomain.INFO)
        loop = WatchdogResearchLoop(providers=[provider], seed=3)
        records = loop.run(steps=4, approved_steps={1, 2, 3, 4})

        assert len(records) == 4

    def test_step_numbers_are_sequential(self) -> None:
        provider = FixedProvider(severity=0.5, confidence=0.7, domain=ThreatDomain.CYBER)
        loop = WatchdogResearchLoop(providers=[provider], seed=7)
        records = loop.run(steps=5, approved_steps={1, 2, 3, 4, 5})

        steps = [r.step for r in records]
        assert steps == [1, 2, 3, 4, 5]


class TestNoSignals:
    def test_no_plan_when_no_signals(self) -> None:
        loop = WatchdogResearchLoop(providers=[EmptyProvider()], seed=1)
        record = loop.run_step()

        assert record.plan is None
        assert record.result is None
        assert record.verification is None

    def test_risk_decays_without_signals(self) -> None:
        provider = FixedProvider(severity=0.8, confidence=0.8, domain=ThreatDomain.BIO)
        loop = WatchdogResearchLoop(providers=[provider], seed=10)

        loop.run_step(approved=True)
        initial_risk = loop.state.risk_index

        loop._providers = [EmptyProvider()]
        loop.run_step()

        assert loop.state.risk_index < initial_risk


class TestMetrics:
    def test_cycle_metrics_populated(self, default_config: ResearchConfig) -> None:
        provider = FixedProvider(severity=0.6, confidence=0.7, domain=ThreatDomain.FINANCE)
        loop = WatchdogResearchLoop(
            providers=[provider], config=default_config, seed=20,
        )
        record = loop.run_step(approved=True)

        m = record.metrics
        assert m.step == 1
        assert m.signals_observed >= 1
        assert m.observed_domains == ("finance",)
        assert m.plan_generated is True
        assert m.execution_status is not None

    def test_risk_trajectory_tracked(self, default_config: ResearchConfig) -> None:
        provider = FixedProvider(severity=0.5, confidence=0.6, domain=ThreatDomain.CLIMATE)
        loop = WatchdogResearchLoop(
            providers=[provider], config=default_config, seed=30,
        )
        loop.run(steps=5, approved_steps={1, 2, 3, 4, 5})

        assert len(loop.state.risk_trajectory) == 5


class TestCandidatePlans:
    def test_multiple_candidates_with_multi_domain_signals(self) -> None:
        providers = [
            FixedProvider(severity=0.9, confidence=0.9, domain=ThreatDomain.CYBER, name="cyber"),
            FixedProvider(severity=0.7, confidence=0.8, domain=ThreatDomain.INFRA, name="infra"),
        ]
        config = ResearchConfig(candidate_plans=3)
        loop = WatchdogResearchLoop(providers=providers, config=config, seed=40)

        record = loop.run_step(approved=True)

        assert len(record.candidates) >= 2
        assert record.plan is not None
        assert record.plan.counterfactual_score > 0


class _InjectedPlanner:
    def create_plan(self, state: WorldState) -> InterventionPlan | None:
        candidates = self.create_candidates(state)
        return candidates[0] if candidates else None

    def create_candidates(self, state: WorldState) -> list[InterventionPlan]:
        if not state.active_threats:
            return []
        return [
            InterventionPlan(
                objective="Injected plan",
                priority=0.5,
                rationale="external planner",
                actions=[
                    PlannedAction(
                        kind=ActionKind.TRIAGE,
                        description="Inspect indicators",
                        target="soc",
                    ),
                ],
                requires_human_review=False,
                counterfactual_score=0.4,
            ),
        ]


class _InjectedEffector:
    def execute(self, plan: InterventionPlan, approved: bool) -> ExecutionResult:
        return ExecutionResult(
            plan_id=plan.plan_id,
            status=ExecutionStatus.EXECUTED,
            action_log=["executed by injected effector"],
            estimated_impact=0.8,
            side_effect_risk=0.1,
        )


def test_loop_accepts_injected_planner_and_effector() -> None:
    provider = FixedProvider(severity=0.8, confidence=0.8, domain=ThreatDomain.CYBER)
    loop = WatchdogResearchLoop(
        providers=[provider],
        config=ResearchConfig(),
        planner=_InjectedPlanner(),
        effector=_InjectedEffector(),
    )
    record = loop.run_step(approved=True)

    assert record.plan is not None
    assert record.plan.objective == "Injected plan"
    assert record.result is not None
    assert record.result.status is ExecutionStatus.EXECUTED


def test_simulation_effector_logs_grounded_action_context() -> None:
    effector = SimulationEffector(config=ResearchConfig(), seed=33)
    plan = InterventionPlan(
        objective="Stabilize credential stuffing burst affecting payments-api-prod.",
        priority=0.6,
        rationale="Grounded cyber incident plan.",
        actions=[
            PlannedAction(
                kind=ActionKind.TRIAGE,
                description="Validate impossible-travel login spike on payments-api-prod.",
                target="payments-api-prod",
            ),
            PlannedAction(
                kind=ActionKind.MONITOR,
                description="Increase telemetry collection on payments-api-prod telemetry.",
                target="payments-api-prod telemetry",
            ),
        ],
        requires_human_review=False,
        primary_domain=ThreatDomain.CYBER,
        counterfactual_score=0.4,
    )

    result = effector.execute(plan, approved=True)

    assert result.action_log
    assert result.action_log[0].startswith("Operational goal:")
    assert "payments-api-prod" in result.action_log[1]
    assert any(
        marker in result.action_log[-1]
        for marker in ("Residual risk watch", "Stability watch", "Side-effect watch")
    )


def test_effective_execution_reduces_post_ingest_risk() -> None:
    provider = FixedProvider(severity=0.9, confidence=0.9, domain=ThreatDomain.CYBER)
    config = ResearchConfig(review_threshold=0.95)

    probe_state = WorldState()
    probe_state.ingest(
        provider.collect(1),
        passive_decay=config.passive_risk_decay,
        risk_blend_alpha=config.risk_blend_alpha,
    )
    ingested_risk = probe_state.risk_index

    loop = WatchdogResearchLoop(providers=[provider], config=config, seed=77)
    record = loop.run_step(approved=True)

    assert record.result is not None
    assert record.verification is not None
    assert record.risk_index < ingested_risk
