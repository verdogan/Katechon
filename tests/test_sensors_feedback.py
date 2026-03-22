from __future__ import annotations

from watchdog_research.domain import ThreatDomain, ThreatSignal
from watchdog_research.loop import WatchdogResearchLoop
from watchdog_research.sensors import (
    CorrelatedSignalProvider,
    EscalatingSignalProvider,
    SyntheticSignalProvider,
)


def test_synthetic_provider_emits_grounded_incident_metadata() -> None:
    provider = SyntheticSignalProvider(
        name="cyber-feed",
        domain=ThreatDomain.CYBER,
        seed=4,
        base_rate=0.0,
    )

    signal = provider.collect(1)[0]

    for key in (
        "asset",
        "location",
        "owner",
        "response_team",
        "monitoring_surface",
        "dependency_hint",
        "incident_type",
        "indicator",
        "incident_id",
    ):
        assert isinstance(signal.metadata[key], str)
    assert signal.metadata["asset"] in signal.summary
    assert signal.metadata["incident_type"] in signal.summary


def test_escalating_provider_keeps_same_incident_context_while_active() -> None:
    provider = EscalatingSignalProvider(
        name="cyber-apt",
        domain=ThreatDomain.CYBER,
        seed=3,
        base_rate=0.0,
    )

    first = provider.collect(1)[0]
    second = provider.collect(2)[0]

    assert first.metadata["asset"] == second.metadata["asset"]
    assert first.metadata["incident_id"] == second.metadata["incident_id"]


def test_escalating_provider_dampens_after_feedback() -> None:
    provider = EscalatingSignalProvider(
        name="cyber-apt",
        domain=ThreatDomain.CYBER,
        seed=1,
        base_rate=0.0,
        escalation_rate=0.12,
        feedback_dampening=1.0,
    )

    provider.collect(1)
    provider.collect(2)
    before = provider.collect(3)[0].metadata["consecutive_active"]

    provider.apply_intervention_feedback(
        domain=ThreatDomain.CYBER,
        estimated_impact=1.0,
        success_probability=1.0,
    )
    after = provider.collect(4)[0].metadata["consecutive_active"]

    assert before >= 3
    assert after == 1


def test_synthetic_provider_dampens_after_feedback() -> None:
    baseline = SyntheticSignalProvider(
        name="cyber-feed",
        domain=ThreatDomain.CYBER,
        seed=9,
        base_rate=0.0,
    )
    damped = SyntheticSignalProvider(
        name="cyber-feed",
        domain=ThreatDomain.CYBER,
        seed=9,
        base_rate=0.0,
    )

    baseline.collect(1)
    damped.collect(1)
    damped.apply_intervention_feedback(
        domain=ThreatDomain.CYBER,
        estimated_impact=1.0,
        success_probability=1.0,
    )

    baseline_signal = baseline.collect(2)[0]
    damped_signals = damped.collect(2)

    if not damped_signals:
        assert baseline_signal.severity > 0.0
        return

    damped_signal = damped_signals[0]
    assert damped_signal.severity < baseline_signal.severity
    assert damped_signal.confidence <= baseline_signal.confidence


def test_correlated_provider_dampens_targeted_domain_after_feedback() -> None:
    baseline = CorrelatedSignalProvider(
        name="cascade-event",
        domains=[ThreatDomain.CYBER, ThreatDomain.INFRA],
        seed=5,
        base_rate=0.0,
    )
    damped = CorrelatedSignalProvider(
        name="cascade-event",
        domains=[ThreatDomain.CYBER, ThreatDomain.INFRA],
        seed=5,
        base_rate=0.0,
    )

    baseline.collect(1)
    damped.collect(1)
    damped.apply_intervention_feedback(
        domain=ThreatDomain.CYBER,
        estimated_impact=0.9,
        success_probability=0.8,
    )

    baseline_signals = {signal.domain: signal for signal in baseline.collect(2)}
    damped_signals = {signal.domain: signal for signal in damped.collect(2)}

    if ThreatDomain.CYBER not in damped_signals:
        assert ThreatDomain.CYBER in baseline_signals
        return

    assert (
        damped_signals[ThreatDomain.CYBER].severity
        < baseline_signals[ThreatDomain.CYBER].severity
    )


class _FeedbackProbeProvider:
    name = "feedback-probe"

    def __init__(self) -> None:
        self.feedback_calls: list[tuple[ThreatDomain, float, float]] = []

    def collect(self, tick: int) -> list[ThreatSignal]:
        return [
            ThreatSignal(
                source=self.name,
                domain=ThreatDomain.CYBER,
                severity=0.8,
                confidence=0.8,
                summary=f"tick={tick}",
            ),
        ]

    def apply_intervention_feedback(
        self,
        domain: ThreatDomain,
        estimated_impact: float,
        success_probability: float,
    ) -> None:
        self.feedback_calls.append((domain, estimated_impact, success_probability))


def test_loop_emits_feedback_to_providers() -> None:
    provider = _FeedbackProbeProvider()
    loop = WatchdogResearchLoop(providers=[provider], seed=99)

    loop.run_step(approved=True)

    assert provider.feedback_calls
    feedback_domain, _, _ = provider.feedback_calls[0]
    assert feedback_domain is ThreatDomain.CYBER
