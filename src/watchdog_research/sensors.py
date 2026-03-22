from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any, Protocol

from .domain import ThreatDomain, ThreatSignal

ASSET_PROFILES: dict[ThreatDomain, tuple[dict[str, str], ...]] = {
    ThreatDomain.CYBER: (
        {
            "asset": "payments-api-prod",
            "location": "us-east-1 payment cluster",
            "owner": "platform-security",
            "response_team": "soc",
            "monitoring_surface": "payments-api-prod telemetry",
            "dependency_hint": "card settlement gateway",
        },
        {
            "asset": "identity-gateway",
            "location": "eu-west-1 auth edge",
            "owner": "identity-ops",
            "response_team": "soc",
            "monitoring_surface": "identity-gateway auth logs",
            "dependency_hint": "single sign-on control plane",
        },
        {
            "asset": "vpn-segment-a",
            "location": "corporate remote access network",
            "owner": "network-security",
            "response_team": "network",
            "monitoring_surface": "vpn-segment-a netflow",
            "dependency_hint": "remote admin jump hosts",
        },
    ),
    ThreatDomain.BIO: (
        {
            "asset": "sequencing-lab-3",
            "location": "northeast pathogen screening center",
            "owner": "biointel-ops",
            "response_team": "biointel",
            "monitoring_surface": "sequencing-lab-3 assay dashboard",
            "dependency_hint": "regional diagnostic batch queue",
        },
        {
            "asset": "cold-chain-route-12",
            "location": "mid-atlantic vaccine corridor",
            "owner": "public-health logistics",
            "response_team": "public-health",
            "monitoring_surface": "cold-chain-route-12 temperature feed",
            "dependency_hint": "vaccine reserve staging hub",
        },
        {
            "asset": "sentinel-clinic-network",
            "location": "southwest triage region",
            "owner": "epidemiology command",
            "response_team": "analytics",
            "monitoring_surface": "sentinel-clinic-network intake stream",
            "dependency_hint": "hospital overflow coordination desk",
        },
    ),
    ThreatDomain.INFRA: (
        {
            "asset": "grid-substation-7",
            "location": "north corridor utility zone",
            "owner": "infrastructure-ops",
            "response_team": "infrastructure",
            "monitoring_surface": "grid-substation-7 scada telemetry",
            "dependency_hint": "metro rail power feed",
        },
        {
            "asset": "water-plant-orion",
            "location": "river basin treatment sector",
            "owner": "municipal resilience",
            "response_team": "ops",
            "monitoring_surface": "water-plant-orion control dashboard",
            "dependency_hint": "downstream pumping stations",
        },
        {
            "asset": "freight-switchyard-4",
            "location": "central freight network",
            "owner": "critical logistics",
            "response_team": "platform",
            "monitoring_surface": "freight-switchyard-4 load monitor",
            "dependency_hint": "port intermodal transfer route",
        },
    ),
    ThreatDomain.INFO: (
        {
            "asset": "election-monitoring-feed",
            "location": "national civic information channel",
            "owner": "trust-safety",
            "response_team": "trust-safety",
            "monitoring_surface": "election-monitoring-feed propagation graph",
            "dependency_hint": "public alert amplification network",
        },
        {
            "asset": "health-advisory-portal",
            "location": "regional public communication stack",
            "owner": "comms-response",
            "response_team": "comms",
            "monitoring_surface": "health-advisory-portal distribution dashboard",
            "dependency_hint": "hospital outreach mailing list",
        },
        {
            "asset": "market-rumor-watch",
            "location": "cross-platform analyst channel",
            "owner": "intel-ops",
            "response_team": "intel",
            "monitoring_surface": "market-rumor-watch trend stream",
            "dependency_hint": "counter-disinformation analyst rotation",
        },
    ),
    ThreatDomain.FINANCE: (
        {
            "asset": "settlement-rail-eu",
            "location": "euro clearing backbone",
            "owner": "finance-ops",
            "response_team": "risk",
            "monitoring_surface": "settlement-rail-eu settlement monitor",
            "dependency_hint": "cross-border liquidity buffer",
        },
        {
            "asset": "counterparty-hub-alpha",
            "location": "derivatives clearing desk",
            "owner": "market-risk",
            "response_team": "finance-ops",
            "monitoring_surface": "counterparty-hub-alpha exposure dashboard",
            "dependency_hint": "high-value collateral pool",
        },
        {
            "asset": "payroll-sync-core",
            "location": "retail payroll settlement lane",
            "owner": "resilience-office",
            "response_team": "resilience",
            "monitoring_surface": "payroll-sync-core transfer monitor",
            "dependency_hint": "critical vendor payment queue",
        },
    ),
    ThreatDomain.CLIMATE: (
        {
            "asset": "coastal-warehouse-hub",
            "location": "gulf logistics corridor",
            "owner": "climate-response",
            "response_team": "climate-ops",
            "monitoring_surface": "coastal-warehouse-hub hazard feed",
            "dependency_hint": "refrigerated supply lanes",
        },
        {
            "asset": "supply-corridor-alpha",
            "location": "western freight wildfire boundary",
            "owner": "field-response",
            "response_team": "field-ops",
            "monitoring_surface": "supply-corridor-alpha weather telemetry",
            "dependency_hint": "fuel resupply convoy route",
        },
        {
            "asset": "river-basin-grid-link",
            "location": "southern drought stress zone",
            "owner": "logistics-command",
            "response_team": "logistics",
            "monitoring_surface": "river-basin-grid-link continuity dashboard",
            "dependency_hint": "water-to-power transfer corridor",
        },
    ),
}

INCIDENT_PROFILES: dict[ThreatDomain, tuple[dict[str, str], ...]] = {
    ThreatDomain.CYBER: (
        {
            "incident_type": "credential stuffing burst",
            "indicator": "impossible-travel login spike",
        },
        {
            "incident_type": "lateral movement probe",
            "indicator": "east-west beaconing cluster",
        },
        {
            "incident_type": "ransomware precursor activity",
            "indicator": "privileged backup tampering attempt",
        },
    ),
    ThreatDomain.BIO: (
        {
            "incident_type": "sample contamination anomaly",
            "indicator": "unexpected assay divergence",
        },
        {
            "incident_type": "cold-chain excursion",
            "indicator": "temperature excursion across storage route",
        },
        {
            "incident_type": "cluster outbreak signal",
            "indicator": "syndromic surveillance spike",
        },
    ),
    ThreatDomain.INFRA: (
        {
            "incident_type": "control-loop desynchronization",
            "indicator": "oscillating supervisory commands",
        },
        {
            "incident_type": "load instability event",
            "indicator": "voltage regulation variance spike",
        },
        {
            "incident_type": "routing bottleneck",
            "indicator": "switchyard throughput collapse",
        },
    ),
    ThreatDomain.INFO: (
        {
            "incident_type": "coordinated false-narrative surge",
            "indicator": "synchronized repost cluster",
        },
        {
            "incident_type": "deepfake amplification campaign",
            "indicator": "high-velocity clip propagation",
        },
        {
            "incident_type": "inauthentic engagement burst",
            "indicator": "sockpuppet account swarm",
        },
    ),
    ThreatDomain.FINANCE: (
        {
            "incident_type": "settlement delay anomaly",
            "indicator": "payment confirmation backlog",
        },
        {
            "incident_type": "counterparty liquidity stress",
            "indicator": "margin call acceleration",
        },
        {
            "incident_type": "market manipulation pattern",
            "indicator": "cross-venue order spoofing signature",
        },
    ),
    ThreatDomain.CLIMATE: (
        {
            "incident_type": "floodplain logistics disruption",
            "indicator": "river gauge threshold breach",
        },
        {
            "incident_type": "wildfire corridor closure risk",
            "indicator": "air quality and wind shift escalation",
        },
        {
            "incident_type": "heatwave power curtailment risk",
            "indicator": "sustained transformer overheat warnings",
        },
    ),
}

CORRELATED_CAMPAIGNS = (
    "cross-domain supply chain cascade",
    "hybrid infrastructure pressure campaign",
    "multi-front continuity breakdown",
)


class SignalProvider(Protocol):
    name: str

    def collect(self, tick: int) -> list[ThreatSignal]:
        """Return signals for a simulation tick."""


class FeedbackSignalProvider(Protocol):
    def apply_intervention_feedback(
        self,
        domain: ThreatDomain,
        estimated_impact: float,
        success_probability: float,
    ) -> None:
        """Apply mission-loop feedback after an intervention cycle."""


IncidentContext = dict[str, str]
SignalMetadata = dict[str, Any]


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))


def _feedback_effectiveness(estimated_impact: float, success_probability: float) -> float:
    return _clamp01((0.55 * success_probability) + (0.45 * estimated_impact))


def _decay_feedback_level(level: float) -> float:
    return level * 0.90


@dataclass(slots=True)
class SyntheticSignalProvider:
    """Stationary-rate signal provider for baseline experiments."""

    name: str
    domain: ThreatDomain
    seed: int
    base_rate: float = 0.60
    feedback_dampening: float = 0.80
    _rng: random.Random = field(init=False, repr=False)
    _suppression_level: float = field(init=False, default=0.0, repr=False)

    def __post_init__(self) -> None:
        self._rng = random.Random(self.seed)

    def collect(self, tick: int) -> list[ThreatSignal]:
        suppression = self._suppression_level
        effective_base_rate = min(0.95, self.base_rate + (suppression * 0.30))
        trigger = self._rng.random() + ((tick % 3) * 0.08)
        self._suppression_level = _decay_feedback_level(suppression)
        if trigger < effective_base_rate:
            return []

        severity = min(1.0, 0.35 + self._rng.random() * 0.65)
        confidence = min(1.0, 0.45 + self._rng.random() * 0.55)
        severity = max(0.10, severity * (1.0 - (suppression * 0.35)))
        confidence = max(0.20, confidence * (1.0 - (suppression * 0.22)))
        metadata: SignalMetadata = {
            **_build_incident_context(self._rng, self.domain, tick=tick),
            "tick": tick,
            "provider": self.name,
            "mode": "synthetic",
        }
        summary = (
            f"{self.name} flagged {metadata['incident_type']} on {metadata['asset']} "
            f"in {metadata['location']}; indicator={metadata['indicator']}."
        )

        return [
            ThreatSignal(
                source=self.name,
                domain=self.domain,
                severity=severity,
                confidence=confidence,
                summary=summary,
                metadata=metadata,
            )
        ]

    def apply_intervention_feedback(
        self,
        domain: ThreatDomain,
        estimated_impact: float,
        success_probability: float,
    ) -> None:
        if domain is not self.domain:
            return
        if estimated_impact <= 0.0 and success_probability <= 0.0:
            return

        effectiveness = _feedback_effectiveness(estimated_impact, success_probability)
        dampening = _clamp01(self.feedback_dampening)
        self._suppression_level = min(
            0.90,
            self._suppression_level + (effectiveness * dampening),
        )


@dataclass(slots=True)
class EscalatingSignalProvider:
    """Signal provider whose severity ramps over consecutive active ticks.

    Models threats that worsen when unaddressed — useful for testing whether
    the loop's adaptation mechanism can keep pace with accelerating risk.
    """

    name: str
    domain: ThreatDomain
    seed: int
    base_rate: float = 0.60
    escalation_rate: float = 0.06
    feedback_dampening: float = 0.70
    _rng: random.Random = field(init=False, repr=False)
    _consecutive_active: int = field(init=False, default=0, repr=False)
    _active_context: IncidentContext | None = field(init=False, default=None, repr=False)

    def __post_init__(self) -> None:
        self._rng = random.Random(self.seed)

    def collect(self, tick: int) -> list[ThreatSignal]:
        trigger = self._rng.random() + ((tick % 4) * 0.06)
        if trigger < self.base_rate:
            self._consecutive_active = 0
            self._active_context = None
            return []

        self._consecutive_active += 1
        if self._active_context is None:
            self._active_context = _build_incident_context(self._rng, self.domain, tick=tick)
        escalation = min(0.35, self._consecutive_active * self.escalation_rate)
        severity = min(1.0, 0.40 + escalation + self._rng.random() * 0.45)
        confidence = min(1.0, 0.50 + self._rng.random() * 0.50)
        assert self._active_context is not None
        metadata: SignalMetadata = {
            **self._active_context,
            "tick": tick,
            "provider": self.name,
            "mode": "escalating",
            "consecutive_active": self._consecutive_active,
        }

        return [
            ThreatSignal(
                source=self.name,
                domain=self.domain,
                severity=severity,
                confidence=confidence,
                summary=(
                    f"{self.name} observed continuing {metadata['incident_type']} on "
                    f"{metadata['asset']} in {metadata['location']} "
                    f"(consecutive={self._consecutive_active}); "
                    f"indicator={metadata['indicator']}."
                ),
                metadata=metadata,
            )
        ]

    def apply_intervention_feedback(
        self,
        domain: ThreatDomain,
        estimated_impact: float,
        success_probability: float,
    ) -> None:
        """Reduce escalation memory when this domain is effectively addressed."""
        if domain is not self.domain:
            return

        if success_probability >= 0.65:
            self._consecutive_active = 0
            self._active_context = None
            return

        if estimated_impact <= 0.0 and success_probability <= 0.0:
            return

        effectiveness = max(0.0, min(1.0, (0.7 * estimated_impact) + (0.3 * success_probability)))
        dampening = max(0.0, min(1.0, self.feedback_dampening))
        reduction = max(1, round(self._consecutive_active * effectiveness * dampening))
        self._consecutive_active = max(0, self._consecutive_active - reduction)


@dataclass(slots=True)
class CorrelatedSignalProvider:
    """Emits correlated signals across multiple domains simultaneously.

    Models coordinated or cascading threat events — e.g., a cyber intrusion
    that triggers infrastructure degradation and information operations.
    """

    name: str
    domains: list[ThreatDomain]
    seed: int
    base_rate: float = 0.40
    correlation_strength: float = 0.85
    feedback_dampening: float = 0.65
    _rng: random.Random = field(init=False, repr=False)
    _campaign_suppression: float = field(init=False, default=0.0, repr=False)
    _domain_suppression: dict[ThreatDomain, float] = field(
        init=False,
        default_factory=dict,
        repr=False,
    )

    def __post_init__(self) -> None:
        self._rng = random.Random(self.seed)

    def collect(self, tick: int) -> list[ThreatSignal]:
        campaign_suppression = self._campaign_suppression
        effective_base_rate = min(0.94, self.base_rate + (campaign_suppression * 0.22))
        trigger = self._rng.random()
        self._campaign_suppression = _decay_feedback_level(campaign_suppression)
        self._domain_suppression = {
            domain: _decay_feedback_level(level)
            for domain, level in self._domain_suppression.items()
            if level > 0.01
        }
        if trigger < effective_base_rate:
            return []

        primary_severity = min(1.0, 0.50 + self._rng.random() * 0.50)
        primary_confidence = min(1.0, 0.55 + self._rng.random() * 0.45)
        primary_severity = max(
            0.12,
            primary_severity * (1.0 - (campaign_suppression * 0.26)),
        )
        primary_confidence = max(
            0.20,
            primary_confidence * (1.0 - (campaign_suppression * 0.16)),
        )
        campaign_name = self._rng.choice(CORRELATED_CAMPAIGNS)
        campaign_id = f"cascade-{tick:03d}-{self._rng.randrange(100, 1000)}"

        signals: list[ThreatSignal] = []
        for i, domain in enumerate(self.domains):
            if i == 0:
                sev, conf = primary_severity, primary_confidence
            else:
                spread = 1.0 - self.correlation_strength
                sev = min(1.0, max(0.1, primary_severity + (self._rng.random() - 0.5) * spread))
                conf = min(1.0, max(0.1, primary_confidence + (self._rng.random() - 0.5) * spread))
            domain_suppression = self._domain_suppression.get(domain, 0.0)
            sev = max(
                0.10,
                sev * (1.0 - (0.22 * campaign_suppression) - (0.28 * domain_suppression)),
            )
            conf = max(
                0.18,
                conf * (1.0 - (0.14 * campaign_suppression) - (0.18 * domain_suppression)),
            )

            metadata: SignalMetadata = {
                **_build_incident_context(self._rng, domain, tick=tick),
                "tick": tick,
                "provider": self.name,
                "mode": "correlated",
                "correlation_index": i,
                "domains_involved": len(self.domains),
                "campaign_name": campaign_name,
                "campaign_id": campaign_id,
            }
            signals.append(
                ThreatSignal(
                    source=self.name,
                    domain=domain,
                    severity=sev,
                    confidence=conf,
                    summary=(
                        f"{self.name} correlated event {campaign_name} hit {metadata['asset']} "
                        f"in {metadata['location']} via {metadata['incident_type']}."
                    ),
                    metadata=metadata,
                )
            )

        return signals

    def apply_intervention_feedback(
        self,
        domain: ThreatDomain,
        estimated_impact: float,
        success_probability: float,
    ) -> None:
        if domain not in self.domains:
            return
        if estimated_impact <= 0.0 and success_probability <= 0.0:
            return

        effectiveness = _feedback_effectiveness(estimated_impact, success_probability)
        dampening = _clamp01(self.feedback_dampening)
        self._campaign_suppression = min(
            0.85,
            self._campaign_suppression + (effectiveness * dampening * 0.70),
        )
        self._domain_suppression[domain] = min(
            0.95,
            self._domain_suppression.get(domain, 0.0) + (effectiveness * dampening),
        )


def _build_incident_context(
    rng: random.Random,
    domain: ThreatDomain,
    tick: int,
) -> IncidentContext:
    profile = dict(rng.choice(ASSET_PROFILES[domain]))
    incident = dict(rng.choice(INCIDENT_PROFILES[domain]))
    context = {**profile, **incident}
    context["incident_id"] = f"{domain.value[:3]}-{tick:03d}-{rng.randrange(100, 1000)}"
    return context
