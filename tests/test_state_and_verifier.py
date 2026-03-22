from __future__ import annotations

from watchdog_research.domain import (
    ExecutionResult,
    ExecutionStatus,
    MissionOutcome,
    ThreatDomain,
    ThreatSignal,
    WorldState,
)
from watchdog_research.verifier import OutcomeVerifier


def test_world_state_blends_risk_across_ticks() -> None:
    state = WorldState()
    signal = ThreatSignal(
        source="weak-feed",
        domain=ThreatDomain.CLIMATE,
        severity=0.4,
        confidence=0.4,
        summary="persistent weak anomaly",
    )

    state.ingest([signal], risk_blend_alpha=0.5)
    first_tick_risk = state.risk_index
    state.ingest([signal], risk_blend_alpha=0.5)
    second_tick_risk = state.risk_index

    assert second_tick_risk > first_tick_risk


def test_verifier_accounts_for_world_state_risk() -> None:
    verifier = OutcomeVerifier()
    result = ExecutionResult(
        plan_id="p1",
        status=ExecutionStatus.SIMULATED,
        action_log=["ok"],
        estimated_impact=0.85,
        side_effect_risk=0.10,
    )

    low_risk_state = WorldState(risk_index=0.10, risk_trajectory=[0.10])
    high_risk_state = WorldState(risk_index=0.90, risk_trajectory=[0.90])

    low = verifier.verify(low_risk_state, result)
    high = verifier.verify(high_risk_state, result)

    assert low.outcome is MissionOutcome.STABILIZED
    assert high.success_probability < low.success_probability
