from __future__ import annotations

from typing import Any

from .config import ResearchConfig
from .domain import ActionKind, InterventionPlan, PlannedAction, ThreatDomain, WorldState
from .openclaw_utils import (
    DEFAULT_GATEWAY_URL,
    DEFAULT_OPENROUTER_MODEL,
    clamp01,
    connect_openclaw_client,
    load_openclaw_client,
    parse_json_object,
    run_coro_sync,
)

DEFAULT_AGENT_ID = "watchdog-planner"

_ACTION_KIND_ALIASES: dict[str, ActionKind] = {
    "triage": ActionKind.TRIAGE,
    "contain": ActionKind.CONTAIN,
    "coordinate": ActionKind.COORDINATE,
    "monitor": ActionKind.MONITOR,
    "recover": ActionKind.RECOVER,
}

_DOMAIN_ALIASES: dict[str, ThreatDomain] = {
    "cyber": ThreatDomain.CYBER,
    "bio": ThreatDomain.BIO,
    "infrastructure": ThreatDomain.INFRA,
    "infra": ThreatDomain.INFRA,
    "information": ThreatDomain.INFO,
    "info": ThreatDomain.INFO,
    "finance": ThreatDomain.FINANCE,
    "climate": ThreatDomain.CLIMATE,
}


class OpenClawPlanner:
    """Mission planner backed by an OpenClaw agent.

    The agent is prompted with the current world state and returns a structured
    JSON plan. The planner remains simulation-only: all effects are still
    evaluated by the framework's effector and verifier.
    """

    def __init__(
        self,
        config: ResearchConfig,
        agent_id: str = DEFAULT_AGENT_ID,
        gateway_url: str = DEFAULT_GATEWAY_URL,
        openrouter_model: str = DEFAULT_OPENROUTER_MODEL,
    ) -> None:
        self._config = config
        self._agent_id = agent_id
        self._gateway_url = gateway_url
        self._openrouter_model = openrouter_model

    def create_plan(self, state: WorldState) -> InterventionPlan | None:
        if not state.active_threats:
            return None
        return run_coro_sync(
            self.acreate_plan(state),
            api_name="OpenClawPlanner.create_plan",
        )

    def create_candidates(self, state: WorldState) -> list[InterventionPlan]:
        plan = self.create_plan(state)
        return [plan] if plan else []

    async def acreate_plan(self, state: WorldState) -> InterventionPlan | None:
        prompt = self._build_prompt(state)
        client_cls = load_openclaw_client()

        client_ctx = await connect_openclaw_client(client_cls, self._gateway_url)
        async with client_ctx as client:
            agent = client.get_agent(self._agent_id)
            result = await agent.execute(prompt)

        if not bool(getattr(result, "success", False)):
            return None

        content = getattr(result, "content", "")
        if not isinstance(content, str):
            return None
        return self._parse_response(content=content, state=state)

    def _build_prompt(self, state: WorldState) -> str:
        signals_text = "\n".join(
            (
                f"  - [{signal.domain.value}] severity={signal.severity:.2f} "
                f"confidence={signal.confidence:.2f} source={signal.source}: "
                f"{signal.summary}"
            )
            for signal in state.active_threats
        )

        action_kinds = ", ".join(kind.value for kind in ActionKind)
        domains = ", ".join(domain.value for domain in ThreatDomain)

        return (
            "You are a mission planner for an active-defense watchdog system.\n\n"
            f"Model preference: {self._openrouter_model} (via OpenRouter).\n\n"
            "Current world state:\n"
            f"  tick: {state.tick}\n"
            f"  risk_index: {state.risk_index:.3f}\n"
            f"  peak_risk: {state.peak_risk:.3f}\n"
            f"  mean_risk: {state.mean_risk:.3f}\n\n"
            f"Active threat signals:\n{signals_text}\n\n"
            "Configuration:\n"
            f"  review_threshold: {self._config.review_threshold}\n"
            f"  max_actions_per_plan: {self._config.max_actions_per_plan}\n\n"
            "Respond with ONLY a JSON object with fields:\n"
            "  objective (string)\n"
            "  domain (one valid domain)\n"
            "  priority (float, 0..1)\n"
            "  rationale (string)\n"
            "  counterfactual_estimate (float, 0..1)\n"
            "  requires_human_review (bool)\n"
            "  actions (array of {kind, description, target})\n\n"
            f"Valid action kinds: {action_kinds}\n"
            f"Valid domains: {domains}\n"
        )

    def _parse_response(self, content: str, state: WorldState) -> InterventionPlan | None:
        payload = parse_json_object(content)
        if payload is None:
            return None

        objective = _coerce_non_empty_str(payload.get("objective"))
        rationale = _coerce_non_empty_str(payload.get("rationale"))

        domain = _parse_domain(payload.get("domain")) or self._top_domain(state)
        priority = clamp01(_coerce_float(payload.get("priority"), default=state.risk_index))
        counterfactual = clamp01(_coerce_float(payload.get("counterfactual_estimate"), default=0.0))

        requires_review = _coerce_bool(
            payload.get("requires_human_review"),
            default=priority >= self._config.review_threshold,
        )
        requires_review = requires_review or priority >= self._config.review_threshold

        actions_data = payload.get("actions")
        if not isinstance(actions_data, list):
            return None

        actions: list[PlannedAction] = []
        for raw_action in actions_data:
            if not isinstance(raw_action, dict):
                continue

            kind = _parse_action_kind(raw_action.get("kind"))
            description = _coerce_non_empty_str(raw_action.get("description"))
            target = _coerce_non_empty_str(raw_action.get("target"))
            if kind is None or description is None or target is None:
                continue

            actions.append(
                PlannedAction(kind=kind, description=description, target=target),
            )
            if len(actions) >= self._config.max_actions_per_plan:
                break

        if not actions:
            return None

        safe_objective = objective or f"Stabilize {domain.value} threat trajectory."
        safe_rationale = rationale or "LLM-generated intervention rationale."

        return InterventionPlan(
            objective=safe_objective,
            priority=priority,
            rationale=safe_rationale,
            actions=actions,
            requires_human_review=requires_review,
            primary_domain=domain,
            counterfactual_score=counterfactual,
            simulation_only=True,
        )

    @staticmethod
    def _top_domain(state: WorldState) -> ThreatDomain:
        if not state.active_threats:
            return ThreatDomain.CYBER
        strongest = max(state.active_threats, key=lambda signal: signal.weighted_score)
        return strongest.domain


def _coerce_non_empty_str(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None


def _coerce_float(value: Any, default: float) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return default
    return default


def _coerce_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "1"}:
            return True
        if lowered in {"false", "no", "0"}:
            return False
    return default


def _parse_action_kind(value: Any) -> ActionKind | None:
    key = _coerce_non_empty_str(value)
    if key is None:
        return None
    return _ACTION_KIND_ALIASES.get(key.lower())


def _parse_domain(value: Any) -> ThreatDomain | None:
    key = _coerce_non_empty_str(value)
    if key is None:
        return None
    return _DOMAIN_ALIASES.get(key.lower())
