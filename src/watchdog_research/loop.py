from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from .config import ResearchConfig
from .control_policies import ControlPolicy, ThresholdGating
from .domain import (
    CycleMetrics,
    ExecutionResult,
    InterventionPlan,
    ThreatSignal,
    VerificationResult,
    WorldState,
)
from .effectors import SimulationEffector
from .planner import MissionPlanner
from .sensors import SignalProvider
from .verifier import OutcomeVerifier


class Planner(Protocol):
    def create_plan(self, state: WorldState) -> InterventionPlan | None:
        """Create the best plan for the current state."""

    def create_candidates(self, state: WorldState) -> list[InterventionPlan]:
        """Create ranked candidate plans for the current state."""


class Effector(Protocol):
    def execute(self, plan: InterventionPlan, approved: bool) -> ExecutionResult:
        """Execute or block an intervention plan."""


@dataclass(slots=True)
class CycleRecord:
    step: int
    signals: list[ThreatSignal]
    plan: InterventionPlan | None
    candidates: list[InterventionPlan]
    result: ExecutionResult | None
    verification: VerificationResult | None
    risk_index: float
    metrics: CycleMetrics
    policy_name: str = ""


class WatchdogResearchLoop:
    def __init__(
        self,
        providers: Sequence[SignalProvider],
        config: ResearchConfig | None = None,
        seed: int = 11,
        planner: Planner | None = None,
        effector: Effector | None = None,
        policy: ControlPolicy | None = None,
    ) -> None:
        self.config = config or ResearchConfig()
        self.state = WorldState()
        self._providers = providers
        self._planner = planner or MissionPlanner(self.config, seed=seed + 50)
        self._effector = effector or SimulationEffector(config=self.config, seed=seed + 101)
        self._policy: ControlPolicy = policy or ThresholdGating(
            threshold=self.config.review_threshold,
        )
        self._verifier = OutcomeVerifier()

    def run_step(self, approved: bool = False) -> CycleRecord:
        prev_risk = self.state.risk_index
        pname = self._policy.name

        signals: list[ThreatSignal] = []
        next_tick = self.state.tick + 1
        for provider in self._providers:
            signals.extend(provider.collect(next_tick))

        self.state.ingest(
            signals,
            passive_decay=self.config.passive_risk_decay,
            risk_blend_alpha=self.config.risk_blend_alpha,
        )

        candidates = self._planner.create_candidates(self.state)
        plan = candidates[0] if candidates else None

        if plan is None:
            metrics = self._build_metrics(
                signals, plan=None, result=None, verification=None,
                prev_risk=prev_risk,
            )
            return CycleRecord(
                step=self.state.tick,
                signals=signals,
                plan=None,
                candidates=[],
                result=None,
                verification=None,
                risk_index=self.state.risk_index,
                metrics=metrics,
                policy_name=pname,
            )

        allow = approved or self._policy.should_allow(plan, self.state)
        result = self._effector.execute(plan=plan, approved=allow)
        verification = self._verifier.verify(self.state, result)
        self._policy.notify_outcome(plan, result, verification)
        self._emit_feedback(plan=plan, result=result, verification=verification)
        self._apply_adaptation(result=result, verification=verification)

        metrics = self._build_metrics(
            signals, plan=plan, result=result, verification=verification,
            prev_risk=prev_risk,
        )

        return CycleRecord(
            step=self.state.tick,
            signals=signals,
            plan=plan,
            candidates=candidates,
            result=result,
            verification=verification,
            risk_index=self.state.risk_index,
            metrics=metrics,
            policy_name=pname,
        )

    def run(
        self,
        steps: int,
        approved_steps: set[int] | None = None,
    ) -> list[CycleRecord]:
        approved_steps = approved_steps or set()
        records: list[CycleRecord] = []
        for _ in range(steps):
            step_number = self.state.tick + 1
            approved = step_number in approved_steps
            records.append(self.run_step(approved=approved))
        return records

    def _apply_adaptation(
        self,
        result: ExecutionResult,
        verification: VerificationResult,
    ) -> None:
        adj = verification.recommended_adjustment
        mitigation = _mitigation_strength(result=result, verification=verification)
        if adj == "stabilize_and_monitor":
            scale = max(
                0.18,
                self.config.stabilize_decay - (0.12 + (0.38 * mitigation)),
            )
            self.state.risk_index = max(0.0, self.state.risk_index * scale)
        elif adj == "reduce_autonomy_and_refine_plan":
            pressure = (1.0 - mitigation) + (0.60 * result.side_effect_risk)
            growth = min(
                1.25,
                self.config.escalation_growth + (0.08 * pressure),
            )
            self.state.risk_index = min(1.0, self.state.risk_index * growth)
        elif adj == "iterate_with_more_context":
            scale = max(0.52, 1.0 - (0.16 + (0.36 * mitigation)))
            self.state.risk_index = max(0.0, self.state.risk_index * scale)

        if self.state.risk_trajectory:
            self.state.risk_trajectory[-1] = self.state.risk_index

    def _emit_feedback(
        self,
        plan: InterventionPlan,
        result: ExecutionResult,
        verification: VerificationResult,
    ) -> None:
        if plan.primary_domain is None:
            return

        for provider in self._providers:
            callback = getattr(provider, "apply_intervention_feedback", None)
            if callback is None:
                continue
            callback(
                domain=plan.primary_domain,
                estimated_impact=result.estimated_impact,
                success_probability=verification.success_probability,
            )

    def _build_metrics(
        self,
        signals: list[ThreatSignal],
        plan: InterventionPlan | None,
        result: ExecutionResult | None,
        verification: VerificationResult | None,
        prev_risk: float,
    ) -> CycleMetrics:
        domains = {s.domain for s in signals}
        observed_domains = tuple(sorted(domain.value for domain in domains))
        return CycleMetrics(
            step=self.state.tick,
            signals_observed=len(signals),
            domains_active=len(domains),
            observed_domains=observed_domains,
            plan_generated=plan is not None,
            execution_status=result.status if result else None,
            estimated_impact=result.estimated_impact if result else 0.0,
            side_effect_risk=result.side_effect_risk if result else 0.0,
            success_probability=verification.success_probability if verification else 0.0,
            risk_index=self.state.risk_index,
            risk_delta=self.state.risk_index - prev_risk,
            outcome=verification.outcome if verification else None,
        )


def _mitigation_strength(
    result: ExecutionResult,
    verification: VerificationResult,
) -> float:
    return max(
        0.0,
        min(
            1.0,
            (0.55 * verification.success_probability)
            + (0.35 * result.estimated_impact)
            - (0.20 * result.side_effect_risk),
        ),
    )
