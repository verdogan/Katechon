from __future__ import annotations

from statistics import mean

import pytest

from watchdog_research.config import ResearchConfig
from watchdog_research.domain import (
    ActionKind,
    CycleMetrics,
    ExecutionResult,
    ExecutionStatus,
    InterventionPlan,
    MissionOutcome,
    PlannedAction,
    ThreatDomain,
    VerificationResult,
)
from watchdog_research.evaluation import compare_evaluations, evaluate_run, format_evaluation
from watchdog_research.loop import CycleRecord, WatchdogResearchLoop
from watchdog_research.scenarios import list_scenarios, load_scenario

from .conftest import FixedProvider


def _make_record(plan_id: str, status: ExecutionStatus) -> CycleRecord:
    plan = InterventionPlan(
        objective="test",
        priority=0.6,
        rationale="test rationale",
        actions=[
            PlannedAction(kind=ActionKind.TRIAGE, description="inspect", target="soc"),
        ],
        requires_human_review=False,
        primary_domain=ThreatDomain.CYBER,
        counterfactual_score=0.4,
        plan_id=plan_id,
    )
    outcome = (
        MissionOutcome.BLOCKED
        if status is ExecutionStatus.BLOCKED_REVIEW
        else MissionOutcome.PARTIAL
    )
    result = ExecutionResult(
        plan_id=plan_id,
        status=status,
        action_log=["test"],
        estimated_impact=0.5 if status is not ExecutionStatus.BLOCKED_REVIEW else 0.0,
        side_effect_risk=0.1,
    )
    verification = VerificationResult(
        success_probability=0.0 if status is ExecutionStatus.BLOCKED_REVIEW else 0.6,
        outcome=outcome,
        recommended_adjustment="test-adjustment",
        notes="test",
    )
    metrics = CycleMetrics(
        step=1,
        signals_observed=1,
        domains_active=1,
        observed_domains=("cyber",),
        plan_generated=True,
        execution_status=status,
        estimated_impact=result.estimated_impact,
        side_effect_risk=result.side_effect_risk,
        success_probability=verification.success_probability,
        risk_index=0.4,
        risk_delta=0.0,
        outcome=verification.outcome,
    )
    return CycleRecord(
        step=1,
        signals=[],
        plan=plan,
        candidates=[plan],
        result=result,
        verification=verification,
        risk_index=0.4,
        metrics=metrics,
        policy_name="test-policy",
    )


class TestEvaluateRun:
    def test_basic_evaluation_fields(self) -> None:
        provider = FixedProvider(severity=0.8, confidence=0.8, domain=ThreatDomain.CYBER)
        loop = WatchdogResearchLoop(
            providers=[provider], config=ResearchConfig(), seed=100,
        )
        records = loop.run(steps=5, approved_steps={1, 2, 3, 4, 5})
        metrics = [r.metrics for r in records]

        ev = evaluate_run(metrics, scenario_name="test")

        assert ev.total_steps == 5
        assert ev.total_signals >= 1
        assert ev.unique_domains_observed >= 1
        assert ev.plans_generated >= 1
        assert 0.0 <= ev.autonomy_ratio <= 1.0
        assert 0.0 <= ev.stabilization_rate <= 1.0

    def test_blocked_runs_lower_autonomy(self) -> None:
        provider = FixedProvider(severity=0.95, confidence=0.95, domain=ThreatDomain.CYBER)
        config = ResearchConfig(review_threshold=0.50)
        loop = WatchdogResearchLoop(
            providers=[provider], config=config, seed=101,
        )
        records = loop.run(steps=5)
        metrics = [r.metrics for r in records]

        ev = evaluate_run(metrics, scenario_name="blocked")

        assert ev.interventions_blocked > 0
        assert ev.autonomy_ratio < 1.0

    def test_adversarial_confusion_metrics(self) -> None:
        records = [
            _make_record("adv-1", ExecutionStatus.BLOCKED_REVIEW),
            _make_record("adv-2", ExecutionStatus.SIMULATED),
            _make_record("legit-1", ExecutionStatus.BLOCKED_REVIEW),
            _make_record("legit-2", ExecutionStatus.SIMULATED),
        ]
        ev = evaluate_run(
            [r.metrics for r in records],
            scenario_name="adversarial-metrics",
            records=records,
            adversarial_log={
                "adv-1": True,
                "adv-2": True,
                "legit-1": False,
                "legit-2": False,
            },
        )

        assert ev.adversarial_plans_total == 2
        assert ev.legitimate_plans_total == 2
        assert ev.true_positive_rate == pytest.approx(0.5)
        assert ev.false_negative_rate == pytest.approx(0.5)
        assert ev.false_positive_rate == pytest.approx(0.5)
        assert ev.true_negative_rate == pytest.approx(0.5)
        assert ev.safety_score == pytest.approx(0.5)
        assert ev.usefulness_score == pytest.approx(0.5)

    def test_non_adversarial_runs_leave_control_metrics_empty(self) -> None:
        provider = FixedProvider(severity=0.8, confidence=0.8, domain=ThreatDomain.CYBER)
        loop = WatchdogResearchLoop(
            providers=[provider], config=ResearchConfig(), seed=102,
        )
        records = loop.run(steps=3, approved_steps={1, 2, 3})

        ev = evaluate_run([r.metrics for r in records], scenario_name="non-adv")

        assert ev.true_positive_rate is None
        assert ev.false_positive_rate is None
        assert ev.safety_score is None
        assert ev.usefulness_score is None


class TestFormatEvaluation:
    def test_format_contains_key_sections(self) -> None:
        provider = FixedProvider(severity=0.6, confidence=0.7, domain=ThreatDomain.INFRA)
        loop = WatchdogResearchLoop(providers=[provider], seed=200)
        records = loop.run(steps=3, approved_steps={1, 2, 3})
        metrics = [r.metrics for r in records]

        ev = evaluate_run(metrics, scenario_name="fmt-test")
        text = format_evaluation(ev)

        assert "fmt-test" in text
        assert "Intervention Summary" in text
        assert "Efficacy Metrics" in text
        assert "Risk Trajectory" in text
        assert "Autonomy" in text

    def test_format_contains_adversarial_section_when_present(self) -> None:
        records = [
            _make_record("adv-1", ExecutionStatus.BLOCKED_REVIEW),
            _make_record("legit-1", ExecutionStatus.SIMULATED),
        ]
        ev = evaluate_run(
            [r.metrics for r in records],
            scenario_name="fmt-adv",
            records=records,
            adversarial_log={"adv-1": True, "legit-1": False},
        )

        text = format_evaluation(ev)

        assert "Adversarial Control Metrics" in text
        assert "True positive rate" in text
        assert "Usefulness score" in text


class TestCompareEvaluations:
    def test_comparison_across_scenarios(self) -> None:
        evaluations = []
        for name in ["baseline", "cyber_escalation"]:
            scenario = load_scenario(name, seed=42)
            loop = WatchdogResearchLoop(
                providers=scenario.providers,
                config=scenario.config,
                seed=scenario.seed,
            )
            records = loop.run(steps=scenario.steps, approved_steps=scenario.approved_steps)
            ev = evaluate_run(
                [r.metrics for r in records],
                scenario_name=scenario.name,
            )
            evaluations.append(ev)

        table = compare_evaluations(evaluations)

        assert "baseline" in table
        assert "cyber_escalation" in table
        assert "Mean impact" in table
        assert " | " in table
        assert "-+-" in table

    def test_comparison_includes_adversarial_rows_when_available(self) -> None:
        records = [
            _make_record("adv-1", ExecutionStatus.BLOCKED_REVIEW),
            _make_record("legit-1", ExecutionStatus.SIMULATED),
        ]
        evaluation = evaluate_run(
            [r.metrics for r in records],
            scenario_name="adv-table",
            records=records,
            adversarial_log={"adv-1": True, "legit-1": False},
        )

        table = compare_evaluations([evaluation])

        assert "TPR" in table
        assert "FPR" in table
        assert "Safety score" in table


class TestScenarioRegistry:
    def test_list_scenarios_non_empty(self) -> None:
        names = list_scenarios()
        assert len(names) >= 5

    def test_new_adversarial_scenarios_are_registered(self) -> None:
        names = set(list_scenarios())
        assert "adversarial_baseline" in names
        assert "adversarial_escalation" in names
        assert "stealth_adversary" in names

    @pytest.mark.parametrize("name", list_scenarios())
    def test_each_scenario_runs_without_error(self, name: str) -> None:
        scenario = load_scenario(name, seed=99)
        loop = WatchdogResearchLoop(
            providers=scenario.providers,
            config=scenario.config,
            seed=scenario.seed,
        )
        records = loop.run(steps=scenario.steps, approved_steps=scenario.approved_steps)

        assert len(records) == scenario.steps
        for r in records:
            assert r.metrics is not None


def test_approved_response_improves_on_baseline_average_risk_reduction() -> None:
    baseline_reductions = []
    approved_reductions = []
    for seed in (42, 43, 44):
        baseline = load_scenario("baseline", seed=seed)
        baseline_loop = WatchdogResearchLoop(
            providers=baseline.providers,
            config=baseline.config,
            seed=baseline.seed,
        )
        baseline_records = baseline_loop.run(
            steps=baseline.steps,
            approved_steps=baseline.approved_steps,
        )
        baseline_reductions.append(
            evaluate_run(
                [record.metrics for record in baseline_records],
                scenario_name=baseline.name,
            ).risk_reduction
        )

        approved = load_scenario("approved_response", seed=seed)
        approved_loop = WatchdogResearchLoop(
            providers=approved.providers,
            config=approved.config,
            seed=approved.seed,
        )
        approved_records = approved_loop.run(
            steps=approved.steps,
            approved_steps=approved.approved_steps,
        )
        approved_reductions.append(
            evaluate_run(
                [record.metrics for record in approved_records],
                scenario_name=approved.name,
            ).risk_reduction
        )

    assert mean(approved_reductions) > mean(baseline_reductions)


def test_cyber_escalation_has_positive_average_risk_reduction() -> None:
    reductions = []
    for seed in (42, 43, 44):
        scenario = load_scenario("cyber_escalation", seed=seed)
        loop = WatchdogResearchLoop(
            providers=scenario.providers,
            config=scenario.config,
            seed=scenario.seed,
        )
        records = loop.run(
            steps=scenario.steps,
            approved_steps=scenario.approved_steps,
        )
        reductions.append(
            evaluate_run(
                [record.metrics for record in records],
                scenario_name=scenario.name,
            ).risk_reduction
        )

    assert mean(reductions) > 0.0
