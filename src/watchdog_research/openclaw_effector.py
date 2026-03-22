from __future__ import annotations

from .config import ResearchConfig
from .domain import (
    ActionKind,
    ExecutionResult,
    ExecutionStatus,
    InterventionPlan,
    PlannedAction,
)
from .openclaw_utils import (
    DEFAULT_GATEWAY_URL,
    DEFAULT_OPENROUTER_MODEL,
    clamp01,
    connect_openclaw_client,
    load_openclaw_client,
    run_coro_sync,
)

DEFAULT_AGENT_ID = "watchdog-executor"

PLAYBOOKS: dict[ActionKind, str] = {
    ActionKind.TRIAGE: (
        "Gather up-to-date threat intelligence for the requested action.\n"
        "Target: {target}\n"
        "Task: {description}\n"
        "Return structured indicators and confidence levels."
    ),
    ActionKind.MONITOR: (
        "Open monitoring sources for the target and summarize current status.\n"
        "Target: {target}\n"
        "Task: {description}\n"
        "Capture anomalies and key metrics."
    ),
    ActionKind.CONTAIN: (
        "Execute containment workflow with strict scope control.\n"
        "Target: {target}\n"
        "Task: {description}\n"
        "Report each step and any errors."
    ),
    ActionKind.COORDINATE: (
        "Send a concise coordination update to the configured response channel.\n"
        "Target: {target}\n"
        "Task: {description}\n"
        "Include risk level and next actions."
    ),
    ActionKind.RECOVER: (
        "Execute recovery workflow for the requested target.\n"
        "Target: {target}\n"
        "Task: {description}\n"
        "Report progress checkpoints and final status."
    ),
}


class OpenClawEffector:
    """Execute intervention plans via OpenClaw tool invocations."""

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

    def execute(self, plan: InterventionPlan, approved: bool) -> ExecutionResult:
        if not approved:
            return ExecutionResult(
                plan_id=plan.plan_id,
                status=ExecutionStatus.BLOCKED_REVIEW,
                action_log=[
                    "Execution blocked by control policy or pending explicit human approval."
                ],
                estimated_impact=0.0,
                side_effect_risk=0.0,
            )
        return run_coro_sync(
            self.aexecute(plan),
            api_name="OpenClawEffector.execute",
        )

    async def aexecute(self, plan: InterventionPlan) -> ExecutionResult:
        action_log: list[str] = []
        attempted = 0
        completed = 0

        client_cls = load_openclaw_client()
        client_ctx = await connect_openclaw_client(client_cls, self._gateway_url)
        async with client_ctx as client:
            agent = client.get_agent(self._agent_id)
            for action in plan.actions:
                attempted += 1
                result = await agent.execute(self._action_to_prompt(action))
                if bool(getattr(result, "success", False)):
                    completed += 1
                    action_log.append(f"[{action.kind.value}] {action.target}: completed")
                    continue

                detail = getattr(result, "content", "")
                if isinstance(detail, str) and detail.strip():
                    trimmed = detail.strip().replace("\n", " ")[:120]
                    action_log.append(
                        f"[{action.kind.value}] {action.target}: failed ({trimmed})",
                    )
                else:
                    action_log.append(f"[{action.kind.value}] {action.target}: failed")

        if attempted == 0:
            return ExecutionResult(
                plan_id=plan.plan_id,
                status=ExecutionStatus.SKIPPED,
                action_log=["No actions supplied in plan."],
                estimated_impact=0.0,
                side_effect_risk=0.0,
            )

        impact = completed / attempted
        side_effect_risk = clamp01(max(0.05, (1.0 - impact) * 0.45))
        return ExecutionResult(
            plan_id=plan.plan_id,
            status=ExecutionStatus.EXECUTED,
            action_log=action_log,
            estimated_impact=impact,
            side_effect_risk=side_effect_risk,
        )

    def _action_to_prompt(self, action: PlannedAction) -> str:
        template = PLAYBOOKS[action.kind]
        action_prompt = template.format(description=action.description, target=action.target)
        return (
            f"Model preference: {self._openrouter_model} (via OpenRouter).\n\n"
            "You are a constrained action executor. "
            "Do only what is requested and report outputs clearly.\n\n"
            f"{action_prompt}"
        )
