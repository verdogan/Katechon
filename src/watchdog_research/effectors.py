from __future__ import annotations

import random

from .config import ResearchConfig
from .domain import ExecutionResult, ExecutionStatus, InterventionPlan


class SimulationEffector:
    """Simulation-only effector.  No live-world actuation is implemented."""

    def __init__(self, config: ResearchConfig, seed: int) -> None:
        self._config = config
        self._rng = random.Random(seed)

    def execute(self, plan: InterventionPlan, approved: bool) -> ExecutionResult:
        if not approved:
            return ExecutionResult(
                plan_id=plan.plan_id,
                status=ExecutionStatus.BLOCKED_REVIEW,
                action_log=[
                    "Execution blocked pending explicit human approval.",
                    f"Blocked plan objective: {plan.objective}",
                ],
                estimated_impact=0.0,
                side_effect_risk=0.0,
            )

        log = [f"Operational goal: {plan.objective}"]
        log.extend(
            _format_action_log_entry(action.description, action.kind.value, action.target)
            for action in plan.actions
        )

        base_impact = min(1.0, (plan.priority * 0.92) + 0.04)
        noise = (self._rng.random() - 0.5) * 2 * self._config.simulate_effector_noise
        impact = max(0.0, min(1.0, base_impact + noise))

        side_effect_risk = max(
            0.0,
            min(1.0, (1.0 - impact) * 0.42 + self._rng.random() * 0.16),
        )
        log.append(
            _build_residual_note(
                plan=plan,
                impact=impact,
                side_effect_risk=side_effect_risk,
            )
        )

        return ExecutionResult(
            plan_id=plan.plan_id,
            status=ExecutionStatus.SIMULATED,
            action_log=log,
            estimated_impact=impact,
            side_effect_risk=side_effect_risk,
        )


def _format_action_log_entry(description: str, action_kind: str, target: str) -> str:
    return f"Simulated {action_kind} on {target}: {description}"


def _build_residual_note(
    plan: InterventionPlan,
    impact: float,
    side_effect_risk: float,
) -> str:
    primary_target = plan.actions[0].target if plan.actions else "affected asset"
    if side_effect_risk >= 0.5:
        return (
            f"Side-effect watch: intervention around {primary_target} may temporarily "
            "degrade dependent services."
        )
    if impact >= 0.65:
        return (
            f"Stability watch: {primary_target} shows strong expected recovery if "
            "follow-up monitoring continues."
        )
    return (
        f"Residual risk watch: continue observing dependencies around {primary_target} "
        "after execution."
    )
