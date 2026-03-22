from __future__ import annotations

import random

from .config import ResearchConfig
from .domain import (
    ActionKind,
    InterventionPlan,
    PlannedAction,
    ThreatDomain,
    ThreatSignal,
    WorldState,
)

ACTION_TEMPLATES: dict[ThreatDomain, list[tuple[ActionKind, str, str]]] = {
    ThreatDomain.CYBER: [
        (ActionKind.TRIAGE, "Correlate indicators and isolate suspicious cluster.", "soc"),
        (ActionKind.CONTAIN, "Simulate segmented network containment strategy.", "network"),
        (ActionKind.MONITOR, "Increase telemetry sampling for affected assets.", "observability"),
    ],
    ThreatDomain.BIO: [
        (ActionKind.TRIAGE, "Cross-check outbreak indicators with confidence filters.", "biointel"),
        (ActionKind.COORDINATE, "Prepare stakeholder notification protocol.", "public-health"),
        (ActionKind.MONITOR, "Increase surveillance cadence in flagged regions.", "analytics"),
    ],
    ThreatDomain.INFRA: [
        (ActionKind.TRIAGE, "Assess critical service dependencies.", "infrastructure"),
        (ActionKind.CONTAIN, "Prepare staged load-shedding simulation plan.", "ops"),
        (ActionKind.RECOVER, "Draft recovery routing options for key services.", "platform"),
    ],
    ThreatDomain.INFO: [
        (ActionKind.TRIAGE, "Map propagation channels and confidence clusters.", "trust-safety"),
        (ActionKind.CONTAIN, "Simulate response playbook for false narrative spread.", "comms"),
        (ActionKind.MONITOR, "Track campaign mutation velocity.", "intel"),
    ],
    ThreatDomain.FINANCE: [
        (ActionKind.TRIAGE, "Assess market stress indicators and exposure overlap.", "risk"),
        (ActionKind.COORDINATE, "Simulate counterparty communication protocol.", "finance-ops"),
        (ActionKind.RECOVER, "Prepare continuity actions for payment rails.", "resilience"),
    ],
    ThreatDomain.CLIMATE: [
        (ActionKind.TRIAGE, "Correlate hazard indicators with infrastructure maps.", "climate-ops"),
        (ActionKind.COORDINATE, "Simulate pre-positioning and alert workflows.", "field-ops"),
        (ActionKind.RECOVER, "Draft continuity plan for critical supply corridors.", "logistics"),
    ],
}

GROUNDED_ACTION_TEMPLATES: dict[ThreatDomain, list[tuple[ActionKind, str, str]]] = {
    ThreatDomain.CYBER: [
        (
            ActionKind.TRIAGE,
            "Validate {indicator} on {asset} with {owner}.",
            "{asset}",
        ),
        (
            ActionKind.CONTAIN,
            "Simulate isolating {asset} in {location} while preserving {dependency_hint}.",
            "{asset}",
        ),
        (
            ActionKind.MONITOR,
            "Increase telemetry collection on {monitoring_surface} and adjacent services.",
            "{monitoring_surface}",
        ),
    ],
    ThreatDomain.BIO: [
        (
            ActionKind.TRIAGE,
            "Validate {indicator} tied to {asset} in {location}.",
            "{asset}",
        ),
        (
            ActionKind.COORDINATE,
            "Prepare containment coordination with {owner} for {asset}.",
            "{response_team}",
        ),
        (
            ActionKind.MONITOR,
            "Increase sampling cadence across {monitoring_surface} and {dependency_hint}.",
            "{monitoring_surface}",
        ),
    ],
    ThreatDomain.INFRA: [
        (
            ActionKind.TRIAGE,
            "Inspect control dependencies around {asset} in {location}.",
            "{asset}",
        ),
        (
            ActionKind.CONTAIN,
            "Simulate staged isolation or load shedding for {asset}.",
            "{asset}",
        ),
        (
            ActionKind.RECOVER,
            "Draft recovery routing for {dependency_hint} if {asset} degrades further.",
            "{dependency_hint}",
        ),
    ],
    ThreatDomain.INFO: [
        (
            ActionKind.TRIAGE,
            "Map propagation linked to {incident_type} across {asset}.",
            "{asset}",
        ),
        (
            ActionKind.CONTAIN,
            "Simulate takedown and friction controls for {asset} in {location}.",
            "{asset}",
        ),
        (
            ActionKind.MONITOR,
            "Increase monitoring on {monitoring_surface} for {indicator}.",
            "{monitoring_surface}",
        ),
    ],
    ThreatDomain.FINANCE: [
        (
            ActionKind.TRIAGE,
            "Validate {indicator} on {asset} with {owner}.",
            "{asset}",
        ),
        (
            ActionKind.COORDINATE,
            "Prepare counterparty coordination for {asset} via {response_team}.",
            "{response_team}",
        ),
        (
            ActionKind.RECOVER,
            "Draft continuity actions for {dependency_hint} if {asset} stalls.",
            "{dependency_hint}",
        ),
    ],
    ThreatDomain.CLIMATE: [
        (
            ActionKind.TRIAGE,
            "Correlate {incident_type} signals around {asset} in {location}.",
            "{asset}",
        ),
        (
            ActionKind.COORDINATE,
            "Simulate field coordination for {asset} with {owner}.",
            "{response_team}",
        ),
        (
            ActionKind.RECOVER,
            "Prepare rerouting for {dependency_hint} affected by {asset}.",
            "{dependency_hint}",
        ),
    ],
}

DEFAULT_GROUNDED_CONTEXT: dict[ThreatDomain, dict[str, str]] = {
    ThreatDomain.CYBER: {
        "asset": "affected cyber asset",
        "location": "primary environment",
        "owner": "platform-security",
        "response_team": "soc",
        "monitoring_surface": "security telemetry",
        "dependency_hint": "downstream critical services",
        "incident_type": "suspicious intrusion activity",
        "indicator": "anomalous network and identity indicators",
    },
    ThreatDomain.BIO: {
        "asset": "affected bio facility",
        "location": "regional health zone",
        "owner": "biointel-ops",
        "response_team": "public-health",
        "monitoring_surface": "surveillance dashboard",
        "dependency_hint": "regional diagnostic capacity",
        "incident_type": "biological anomaly",
        "indicator": "elevated outbreak indicators",
    },
    ThreatDomain.INFRA: {
        "asset": "critical infrastructure node",
        "location": "service region",
        "owner": "infrastructure-ops",
        "response_team": "ops",
        "monitoring_surface": "operations telemetry",
        "dependency_hint": "dependent services",
        "incident_type": "infrastructure instability",
        "indicator": "control and capacity variance",
    },
    ThreatDomain.INFO: {
        "asset": "affected information channel",
        "location": "public communications network",
        "owner": "trust-safety",
        "response_team": "comms",
        "monitoring_surface": "distribution dashboard",
        "dependency_hint": "public alert channels",
        "incident_type": "information operation",
        "indicator": "coordinated amplification pattern",
    },
    ThreatDomain.FINANCE: {
        "asset": "financial settlement asset",
        "location": "market operations stack",
        "owner": "market-risk",
        "response_team": "finance-ops",
        "monitoring_surface": "settlement monitor",
        "dependency_hint": "critical payment obligations",
        "incident_type": "financial instability signal",
        "indicator": "abnormal settlement and liquidity markers",
    },
    ThreatDomain.CLIMATE: {
        "asset": "climate-exposed logistics asset",
        "location": "continuity planning region",
        "owner": "climate-response",
        "response_team": "field-ops",
        "monitoring_surface": "hazard telemetry",
        "dependency_hint": "supply continuity routes",
        "incident_type": "climate disruption risk",
        "indicator": "environmental hazard escalation",
    },
}


class MissionPlanner:
    def __init__(self, config: ResearchConfig, seed: int = 0) -> None:
        self._config = config
        self._rng = random.Random(seed)

    def create_plan(self, state: WorldState) -> InterventionPlan | None:
        if not state.active_threats:
            return None

        candidates = self._generate_candidates(state)
        return self._rank_candidates(candidates)[0]

    def create_candidates(self, state: WorldState) -> list[InterventionPlan]:
        """Expose ranked candidate plans for inspection and evaluation."""
        if not state.active_threats:
            return []
        return self._rank_candidates(self._generate_candidates(state))

    def _generate_candidates(self, state: WorldState) -> list[InterventionPlan]:
        ranked_signals = sorted(
            state.active_threats,
            key=lambda s: s.weighted_score,
            reverse=True,
        )

        candidates: list[InterventionPlan] = []
        seen_domains: set[ThreatDomain] = set()

        for signal in ranked_signals:
            if signal.domain in seen_domains:
                continue
            seen_domains.add(signal.domain)

            plan = self._plan_for_signal(signal, state)
            candidates.append(plan)

            if len(candidates) >= self._config.candidate_plans:
                break

        return candidates

    def _plan_for_signal(
        self,
        signal: ThreatSignal,
        state: WorldState,
    ) -> InterventionPlan:
        priority = min(1.0, signal.weighted_score + (state.risk_index * 0.25))
        requires_review = priority >= self._config.review_threshold
        grounded_context = _grounded_signal_context(signal)
        actions = _build_actions_for_signal(
            signal=signal,
            max_actions=self._config.max_actions_per_plan,
            grounded_context=grounded_context,
        )

        cf_score = self._counterfactual_score(signal, state)
        if grounded_context is None:
            objective = f"Stabilize {signal.domain.value} threat trajectory from {signal.source}."
            rationale = (
                f"Primary signal score={signal.weighted_score:.2f}; "
                f"global risk index={state.risk_index:.2f}; "
                f"counterfactual={cf_score:.2f}."
            )
        else:
            objective = (
                f"Stabilize {grounded_context['incident_type']} affecting "
                f"{grounded_context['asset']} in {grounded_context['location']}."
            )
            rationale = (
                f"Indicator={grounded_context['indicator']}; "
                f"weighted score={signal.weighted_score:.2f}; "
                f"global risk index={state.risk_index:.2f}; "
                f"counterfactual={cf_score:.2f}; "
                f"owner={grounded_context['owner']}; "
                f"dependency={grounded_context['dependency_hint']}."
            )

        return InterventionPlan(
            objective=objective,
            priority=priority,
            rationale=rationale,
            actions=actions,
            requires_human_review=requires_review,
            primary_domain=signal.domain,
            counterfactual_score=cf_score,
            simulation_only=True,
        )

    def _counterfactual_score(self, signal: ThreatSignal, state: WorldState) -> float:
        """Estimate expected risk reduction if this signal's threat is addressed.

        Higher values mean intervening on this signal is expected to produce a
        larger improvement in the global risk posture.
        """
        domain_weight = state.domain_weights.get(signal.domain, 1.0)
        base = signal.weighted_score * domain_weight
        discount = self._config.counterfactual_discount
        noise = (self._rng.random() - 0.5) * 0.1
        return max(0.0, min(1.0, base * (1.0 - discount) + noise))

    @staticmethod
    def _rank_candidates(candidates: list[InterventionPlan]) -> list[InterventionPlan]:
        return sorted(
            candidates,
            key=lambda p: (p.counterfactual_score, p.priority),
            reverse=True,
        )


def _grounded_signal_context(signal: ThreatSignal) -> dict[str, str] | None:
    asset = signal.metadata.get("asset")
    incident_type = signal.metadata.get("incident_type")
    if not isinstance(asset, str) or not asset:
        return None
    if not isinstance(incident_type, str) or not incident_type:
        return None

    context = dict(DEFAULT_GROUNDED_CONTEXT[signal.domain])
    for key in context:
        value = signal.metadata.get(key)
        if isinstance(value, str) and value:
            context[key] = value
    return context


def _build_actions_for_signal(
    signal: ThreatSignal,
    max_actions: int,
    grounded_context: dict[str, str] | None,
) -> list[PlannedAction]:
    if grounded_context is None:
        templates = ACTION_TEMPLATES[signal.domain][:max_actions]
        return [
            PlannedAction(kind=kind, description=description, target=target)
            for kind, description, target in templates
        ]

    templates = GROUNDED_ACTION_TEMPLATES[signal.domain][:max_actions]
    return [
        PlannedAction(
            kind=kind,
            description=description.format(**grounded_context),
            target=target.format(**grounded_context),
        )
        for kind, description, target in templates
    ]
