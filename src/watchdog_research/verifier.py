from __future__ import annotations

from .domain import (
    ExecutionResult,
    ExecutionStatus,
    MissionOutcome,
    VerificationResult,
    WorldState,
)


class OutcomeVerifier:
    def verify(self, state: WorldState, result: ExecutionResult) -> VerificationResult:
        if result.status is ExecutionStatus.BLOCKED_REVIEW:
            return VerificationResult(
                success_probability=0.0,
                outcome=MissionOutcome.BLOCKED,
                recommended_adjustment="escalate_for_review",
                notes="No execution occurred. Human review is required before action.",
            )

        base_success = max(
            0.0,
            min(1.0, result.estimated_impact * (1.0 - 0.30 * result.side_effect_risk)),
        )
        risk_memory = max(0.0, state.peak_risk - state.risk_index)
        risk_penalty = (state.risk_index * 0.10) + (risk_memory * 0.04)
        success = max(0.0, min(1.0, base_success - risk_penalty))

        if success >= 0.60 and result.side_effect_risk < 0.50 and state.risk_index < 0.85:
            return VerificationResult(
                success_probability=success,
                outcome=MissionOutcome.STABILIZED,
                recommended_adjustment="stabilize_and_monitor",
                notes=(
                    "Execution appears effective under current risk conditions "
                    f"(risk={state.risk_index:.2f}, peak={state.peak_risk:.2f})."
                ),
            )

        if result.side_effect_risk >= 0.6 or (state.risk_index >= 0.80 and success < 0.55):
            return VerificationResult(
                success_probability=success,
                outcome=MissionOutcome.INEFFECTIVE,
                recommended_adjustment="reduce_autonomy_and_refine_plan",
                notes=(
                    "Outcome is ineffective under elevated contextual risk; "
                    "tighten scope and reduce autonomy."
                ),
            )

        return VerificationResult(
            success_probability=success,
            outcome=MissionOutcome.PARTIAL,
            recommended_adjustment="iterate_with_more_context",
            notes=(
                "Mixed outcome relative to the current risk trajectory; "
                "collect more signals and re-plan."
            ),
        )
