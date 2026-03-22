from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4


class ThreatDomain(StrEnum):
    CYBER = "cyber"
    BIO = "bio"
    INFRA = "infrastructure"
    INFO = "information"
    FINANCE = "finance"
    CLIMATE = "climate"


class ActionKind(StrEnum):
    TRIAGE = "triage"
    CONTAIN = "contain"
    COORDINATE = "coordinate"
    MONITOR = "monitor"
    RECOVER = "recover"


class ExecutionStatus(StrEnum):
    SIMULATED = "simulated"
    EXECUTED = "executed"
    BLOCKED_REVIEW = "blocked_review"
    SKIPPED = "skipped"


class MissionOutcome(StrEnum):
    STABILIZED = "stabilized"
    PARTIAL = "partial"
    INEFFECTIVE = "ineffective"
    BLOCKED = "blocked"


@dataclass(slots=True)
class ThreatSignal:
    source: str
    domain: ThreatDomain
    severity: float
    confidence: float
    summary: str
    metadata: dict[str, Any] = field(default_factory=dict)
    signal_id: str = field(default_factory=lambda: str(uuid4()))
    detected_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def weighted_score(self) -> float:
        return max(0.0, min(1.0, self.severity * self.confidence))


@dataclass(slots=True)
class PlannedAction:
    kind: ActionKind
    description: str
    target: str


@dataclass(slots=True)
class InterventionPlan:
    objective: str
    priority: float
    rationale: str
    actions: list[PlannedAction]
    requires_human_review: bool
    primary_domain: ThreatDomain | None = None
    counterfactual_score: float = 0.0
    simulation_only: bool = True
    plan_id: str = field(default_factory=lambda: str(uuid4()))
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(slots=True)
class ExecutionResult:
    plan_id: str
    status: ExecutionStatus
    action_log: list[str]
    estimated_impact: float
    side_effect_risk: float
    executed_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(slots=True)
class VerificationResult:
    success_probability: float
    outcome: MissionOutcome
    recommended_adjustment: str
    notes: str
    verified_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(slots=True)
class CycleMetrics:
    """Per-cycle quantitative measurements for evaluation pipelines."""

    step: int
    signals_observed: int
    domains_active: int
    observed_domains: tuple[str, ...]
    plan_generated: bool
    execution_status: ExecutionStatus | None
    estimated_impact: float
    side_effect_risk: float
    success_probability: float
    risk_index: float
    risk_delta: float
    outcome: MissionOutcome | None


@dataclass(slots=True)
class WorldState:
    tick: int = 0
    risk_index: float = 0.0
    risk_trajectory: list[float] = field(default_factory=list)
    active_threats: list[ThreatSignal] = field(default_factory=list)
    domain_weights: dict[ThreatDomain, float] = field(
        default_factory=lambda: {
            ThreatDomain.CYBER: 1.0,
            ThreatDomain.BIO: 1.1,
            ThreatDomain.INFRA: 1.05,
            ThreatDomain.INFO: 0.95,
            ThreatDomain.FINANCE: 1.0,
            ThreatDomain.CLIMATE: 1.1,
        }
    )

    def ingest(
        self,
        signals: list[ThreatSignal],
        passive_decay: float = 0.9,
        risk_blend_alpha: float = 0.65,
    ) -> None:
        self.tick += 1
        self.active_threats = signals
        if not signals:
            self.risk_index = max(0.0, self.risk_index * passive_decay)
            self.risk_trajectory.append(self.risk_index)
            return

        weighted = []
        for signal in signals:
            domain_weight = self.domain_weights.get(signal.domain, 1.0)
            weighted.append(signal.weighted_score * domain_weight)

        alpha = max(0.0, min(1.0, risk_blend_alpha))
        new_signal_risk = sum(weighted) / len(weighted)
        blended = (alpha * new_signal_risk) + ((1.0 - alpha) * self.risk_index)
        self.risk_index = max(0.0, min(1.0, blended))
        self.risk_trajectory.append(self.risk_index)

    @property
    def peak_risk(self) -> float:
        return max(self.risk_trajectory) if self.risk_trajectory else 0.0

    @property
    def mean_risk(self) -> float:
        if not self.risk_trajectory:
            return 0.0
        return sum(self.risk_trajectory) / len(self.risk_trajectory)
