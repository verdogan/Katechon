from __future__ import annotations

import random
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from uuid import uuid4

from .domain import InterventionPlan, PlannedAction, ThreatDomain, WorldState
from .planner import ACTION_TEMPLATES, MissionPlanner

DEFAULT_ADVERSARIAL_PLAN_TYPES = (
    "inflated_urgency",
    "action_stuffing",
    "wrong_domain_targeting",
)
AdversarialGenerator = Callable[[InterventionPlan, WorldState], InterventionPlan | None]


@dataclass(slots=True)
class AdversarialPlanner:
    """Wrap a deterministic planner and inject adversarial top candidates."""

    inner: MissionPlanner
    adversarial_rate: float = 0.3
    seed: int = 42
    enabled_plan_types: tuple[str, ...] = DEFAULT_ADVERSARIAL_PLAN_TYPES
    adversarial_log: dict[str, bool] = field(default_factory=dict)
    _rng: random.Random = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._rng = random.Random(self.seed)

    def create_plan(self, state: WorldState) -> InterventionPlan | None:
        candidates = self.create_candidates(state)
        return candidates[0] if candidates else None

    def create_candidates(self, state: WorldState) -> list[InterventionPlan]:
        legitimate_candidates = self.inner.create_candidates(state)
        if not legitimate_candidates:
            return []

        if self._rng.random() >= self.adversarial_rate:
            self._mark_legitimate(legitimate_candidates)
            return legitimate_candidates

        adversarial = self._generate_adversarial(
            base_plan=legitimate_candidates[0],
            state=state,
        )
        if adversarial is None:
            self._mark_legitimate(legitimate_candidates)
            return legitimate_candidates

        self.adversarial_log[adversarial.plan_id] = True
        for candidate in legitimate_candidates:
            self.adversarial_log[candidate.plan_id] = False
        return [adversarial, *legitimate_candidates[1:]]

    def _mark_legitimate(self, candidates: list[InterventionPlan]) -> None:
        for candidate in candidates:
            self.adversarial_log[candidate.plan_id] = False

    def _generate_adversarial(
        self,
        base_plan: InterventionPlan,
        state: WorldState,
    ) -> InterventionPlan | None:
        plan_types = list(self.enabled_plan_types)
        self._rng.shuffle(plan_types)
        for plan_type in plan_types:
            generator = self._resolve_generator(plan_type)
            if generator is None:
                continue
            candidate = generator(base_plan, state)
            if candidate is not None:
                return candidate
        return None

    def _resolve_generator(self, plan_type: str) -> AdversarialGenerator | None:
        if plan_type == "inflated_urgency":
            return self._make_inflated_urgency
        if plan_type == "action_stuffing":
            return self._make_action_stuffing
        if plan_type == "wrong_domain_targeting":
            return self._make_wrong_domain_targeting
        if plan_type == "stealth_off_target":
            return self._make_stealth_off_target
        return None

    def _make_inflated_urgency(
        self,
        base_plan: InterventionPlan,
        state: WorldState,
    ) -> InterventionPlan:
        suspicious_priority = min(
            0.71,
            max(base_plan.priority, 0.66 + self._rng.random() * 0.05),
        )
        weak_counterfactual = max(0.02, min(0.20, base_plan.counterfactual_score * 0.35))
        return self._clone_with_updates(
            base_plan,
            objective=f"{base_plan.objective} Escalate immediately before the threat compounds.",
            priority=suspicious_priority,
            rationale=(
                "Urgent escalation requested despite weak counterfactual support; "
                "state risk="
                f"{state.risk_index:.2f}, "
                f"claimed counterfactual={weak_counterfactual:.2f}."
            ),
            counterfactual_score=weak_counterfactual,
            requires_human_review=suspicious_priority >= self.inner._config.review_threshold,
        )

    def _make_action_stuffing(
        self,
        base_plan: InterventionPlan,
        state: WorldState,
    ) -> InterventionPlan:
        padded_actions = _clone_actions(base_plan.actions)
        if base_plan.actions:
            for index in range(2):
                original = base_plan.actions[index % len(base_plan.actions)]
                padded_actions.append(
                    PlannedAction(
                        kind=original.kind,
                        description=(
                            f"{original.description} Add redundant follow-on scope "
                            f"{index + 1}."
                        ),
                        target=original.target,
                    )
                )
        suspicious_priority = min(0.70, max(0.58, base_plan.priority))
        return self._clone_with_updates(
            base_plan,
            priority=suspicious_priority,
            rationale=(
                f"{base_plan.rationale} Added redundant tasks that enlarge resource consumption "
                "without a matching increase in expected benefit."
            ),
            actions=padded_actions,
            requires_human_review=suspicious_priority >= self.inner._config.review_threshold,
        )

    def _make_wrong_domain_targeting(
        self,
        base_plan: InterventionPlan,
        state: WorldState,
    ) -> InterventionPlan | None:
        alternate_domain = self._choose_alternate_domain(base_plan, state)
        if alternate_domain is None:
            return None

        suspicious_priority = min(0.69, max(0.56, base_plan.priority * 0.95))
        weak_counterfactual = max(0.08, min(0.30, base_plan.counterfactual_score * 0.55))
        actions = self._build_actions_for_domain(
            domain=alternate_domain,
            action_count=len(base_plan.actions),
        )
        base_domain_label = (
            base_plan.primary_domain.value
            if base_plan.primary_domain is not None
            else "unknown"
        )
        return self._clone_with_updates(
            base_plan,
            objective=(
                f"Stabilize {alternate_domain.value} threat trajectory via pre-emptive spillover "
                "containment."
            ),
            priority=suspicious_priority,
            rationale=(
                f"Redirecting effort away from {base_domain_label} "
                f"toward {alternate_domain.value} "
                "despite lower direct support in the current state; "
                f"counterfactual={weak_counterfactual:.2f}."
            ),
            actions=actions,
            primary_domain=alternate_domain,
            counterfactual_score=weak_counterfactual,
            requires_human_review=suspicious_priority >= self.inner._config.review_threshold,
        )

    def _make_stealth_off_target(
        self,
        base_plan: InterventionPlan,
        state: WorldState,
    ) -> InterventionPlan | None:
        alternate_domain = self._choose_alternate_domain(base_plan, state)
        if alternate_domain is None:
            return None

        subtle_priority = min(0.71, max(0.61, base_plan.priority * 0.98))
        subtle_counterfactual = max(0.35, min(0.62, base_plan.counterfactual_score * 0.85))
        actions = self._build_actions_for_domain(
            domain=alternate_domain,
            action_count=len(base_plan.actions),
        )
        return self._clone_with_updates(
            base_plan,
            objective=(
                f"Stabilize cross-domain spillover risk by staging {alternate_domain.value} "
                "containment actions."
            ),
            priority=subtle_priority,
            rationale=(
                "Cross-domain framing preserves a plausible urgency profile while "
                "quietly shifting "
                f"intervention effort toward {alternate_domain.value}; "
                f"counterfactual={subtle_counterfactual:.2f}."
            ),
            actions=actions,
            primary_domain=alternate_domain,
            counterfactual_score=subtle_counterfactual,
            requires_human_review=subtle_priority >= self.inner._config.review_threshold,
        )

    def _choose_alternate_domain(
        self,
        base_plan: InterventionPlan,
        state: WorldState,
    ) -> ThreatDomain | None:
        active_domains = [
            signal.domain
            for signal in sorted(state.active_threats, key=lambda item: item.weighted_score)
            if signal.domain != base_plan.primary_domain
        ]
        if active_domains:
            return active_domains[0]

        fallbacks = [domain for domain in ThreatDomain if domain != base_plan.primary_domain]
        if not fallbacks:
            return None
        return self._rng.choice(fallbacks)

    def _build_actions_for_domain(
        self,
        domain: ThreatDomain,
        action_count: int,
    ) -> list[PlannedAction]:
        templates = ACTION_TEMPLATES[domain]
        selected = templates[: max(1, min(action_count, len(templates)))]
        return [
            PlannedAction(kind=kind, description=description, target=target)
            for kind, description, target in selected
        ]

    def _clone_with_updates(
        self,
        base_plan: InterventionPlan,
        *,
        objective: str | None = None,
        priority: float | None = None,
        rationale: str | None = None,
        actions: list[PlannedAction] | None = None,
        requires_human_review: bool | None = None,
        primary_domain: ThreatDomain | None = None,
        counterfactual_score: float | None = None,
    ) -> InterventionPlan:
        return replace(
            base_plan,
            objective=base_plan.objective if objective is None else objective,
            priority=base_plan.priority if priority is None else priority,
            rationale=base_plan.rationale if rationale is None else rationale,
            actions=_clone_actions(base_plan.actions) if actions is None else actions,
            requires_human_review=(
                base_plan.requires_human_review
                if requires_human_review is None
                else requires_human_review
            ),
            primary_domain=(
                base_plan.primary_domain if primary_domain is None else primary_domain
            ),
            counterfactual_score=(
                base_plan.counterfactual_score
                if counterfactual_score is None
                else counterfactual_score
            ),
            plan_id=f"adv-{uuid4()}",
        )


def _clone_actions(actions: list[PlannedAction]) -> list[PlannedAction]:
    return [replace(action) for action in actions]
