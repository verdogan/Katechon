from __future__ import annotations

import argparse
from pathlib import Path

from .adversarial_planner import (
    DEFAULT_ADVERSARIAL_PLAN_TYPES,
    AdversarialPlanner,
)
from .config import ResearchConfig
from .control_policies import BUILTIN_POLICIES, ControlPolicy, build_policy
from .domain import ThreatDomain
from .effectors import SimulationEffector
from .evaluation import (
    RunEvaluation,
    aggregate_run_evaluations,
    compare_evaluations,
    evaluate_run,
)
from .loop import Planner, WatchdogResearchLoop
from .openclaw_effector import OpenClawEffector
from .openclaw_planner import OpenClawPlanner
from .openclaw_sensors import OpenClawSensor
from .openclaw_utils import DEFAULT_GATEWAY_URL, DEFAULT_OPENROUTER_MODEL
from .planner import MissionPlanner
from .reporting import records_to_markdown, write_json, write_markdown
from .scenarios import Scenario, list_scenarios, load_scenario
from .sensors import SignalProvider, SyntheticSignalProvider

PLANNER_CHOICES = ("deterministic", "adversarial", "openclaw")
EFFECTOR_CHOICES = ("simulation", "openclaw")
SENSOR_MODE_CHOICES = ("synthetic", "openclaw")
POLICY_CHOICES = tuple(BUILTIN_POLICIES.keys())

DEFAULT_PLANNER_AGENT_ID = "watchdog-planner"
DEFAULT_EFFECTOR_AGENT_ID = "watchdog-executor"
DEFAULT_SENSOR_AGENT_ID = "watchdog-sensor"


def _parse_approved_steps(raw: str) -> set[int]:
    if not raw.strip():
        return set()
    parts = [item.strip() for item in raw.split(",")]
    return {int(item) for item in parts if item}


def _parse_seeds(raw: str, default_seed: int = 42) -> list[int]:
    """Parse --seeds: comma-separated list, or single int N for N seeds from default."""
    raw = raw.strip()
    if not raw:
        return [default_seed]
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    if len(parts) == 1 and parts[0].isdigit():
        n = int(parts[0])
        if n <= 0:
            return [default_seed]
        return [default_seed + i for i in range(n)]
    return [int(p) for p in parts]


def _add_component_flags(
    parser: argparse.ArgumentParser,
    include_sensor_mode: bool,
) -> None:
    parser.add_argument(
        "--policy",
        type=str,
        choices=POLICY_CHOICES,
        default="threshold",
        help="Control policy for execution gating.",
    )
    parser.add_argument(
        "--planner",
        type=str,
        choices=PLANNER_CHOICES,
        default=None,
        help="Planner backend. Defaults to the scenario planner when available.",
    )
    parser.add_argument(
        "--effector",
        type=str,
        choices=EFFECTOR_CHOICES,
        default="simulation",
        help="Effector backend: simulation or OpenClaw executor.",
    )
    parser.add_argument(
        "--openclaw-gateway-url",
        type=str,
        default=DEFAULT_GATEWAY_URL,
        help="OpenClaw gateway WebSocket URL.",
    )
    parser.add_argument(
        "--planner-agent-id",
        type=str,
        default=DEFAULT_PLANNER_AGENT_ID,
        help="OpenClaw planner agent ID.",
    )
    parser.add_argument(
        "--effector-agent-id",
        type=str,
        default=DEFAULT_EFFECTOR_AGENT_ID,
        help="OpenClaw effector agent ID.",
    )
    parser.add_argument(
        "--planner-model",
        type=str,
        default=DEFAULT_OPENROUTER_MODEL,
        help="OpenRouter model hint for planner prompts.",
    )
    parser.add_argument(
        "--effector-model",
        type=str,
        default=DEFAULT_OPENROUTER_MODEL,
        help="OpenRouter model hint for effector prompts.",
    )
    if include_sensor_mode:
        parser.add_argument(
            "--sensor-mode",
            type=str,
            choices=SENSOR_MODE_CHOICES,
            default="synthetic",
            help="Default run sensors: synthetic providers or OpenClaw sensors.",
        )
        parser.add_argument(
            "--sensor-agent-id",
            type=str,
            default=DEFAULT_SENSOR_AGENT_ID,
            help="OpenClaw sensor agent ID.",
        )
        parser.add_argument(
            "--sensor-model",
            type=str,
            default=DEFAULT_OPENROUTER_MODEL,
            help="OpenRouter model hint for sensor prompts.",
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="watchdog-research",
        description="Run the exploratory active-defense watchdog simulation.",
    )
    sub = parser.add_subparsers(dest="command")

    # --- run command (default behaviour) ---
    run_p = sub.add_parser("run", help="Execute a simulation run.")
    run_p.add_argument("--steps", type=int, default=5)
    run_p.add_argument("--seed", type=int, default=42)
    run_p.add_argument("--approved-steps", type=str, default="")
    run_p.add_argument("--output", type=str, default="")
    run_p.add_argument("--json-output", type=str, default="")
    _add_component_flags(run_p, include_sensor_mode=True)

    # --- scenario command ---
    sc_p = sub.add_parser("scenario", help="Run a predefined scenario.")
    sc_p.add_argument("name", type=str, help="Scenario name.")
    sc_p.add_argument("--seed", type=int, default=42)
    sc_p.add_argument("--output", type=str, default="")
    sc_p.add_argument("--json-output", type=str, default="")
    _add_component_flags(sc_p, include_sensor_mode=False)

    # --- evaluate command ---
    ev_p = sub.add_parser("evaluate", help="Run all scenarios and compare.")
    ev_p.add_argument("--seed", type=int, default=42)
    ev_p.add_argument(
        "--seeds",
        type=str,
        default="",
        help="Comma-separated seeds or count (e.g. 5 for 5 seeds).",
    )
    ev_p.add_argument("--output", type=str, default="")
    _add_component_flags(ev_p, include_sensor_mode=False)

    # --- compare-policies command ---
    cp_p = sub.add_parser(
        "compare-policies",
        help="Run a scenario with each control policy and compare.",
    )
    cp_p.add_argument("name", type=str, help="Scenario name.")
    cp_p.add_argument("--seed", type=int, default=42)
    cp_p.add_argument(
        "--seeds",
        type=str,
        default="",
        help="Comma-separated seeds or count (e.g. 5 for 5 seeds).",
    )
    cp_p.add_argument("--output", type=str, default="")
    cp_p.add_argument(
        "--policies",
        type=str,
        default="",
        help="Comma-separated policy names (default: all).",
    )
    _add_component_flags(cp_p, include_sensor_mode=False)

    # --- list command ---
    sub.add_parser("list", help="List available scenarios.")

    # Backward-compat: bare flags for simple runs
    parser.add_argument("--steps", type=int, default=5)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--approved-steps", type=str, default="")
    parser.add_argument("--output", type=str, default="")
    parser.add_argument("--json-output", type=str, default="")
    _add_component_flags(parser, include_sensor_mode=True)

    return parser


def _build_default_providers(args: argparse.Namespace) -> list[SignalProvider]:
    if args.sensor_mode == "openclaw":
        return _build_openclaw_default_providers(args)
    return _build_synthetic_default_providers(seed=args.seed)


def _build_synthetic_default_providers(seed: int) -> list[SignalProvider]:
    return [
        SyntheticSignalProvider("cyber-feed", ThreatDomain.CYBER, seed=seed + 1),
        SyntheticSignalProvider("infra-feed", ThreatDomain.INFRA, seed=seed + 2),
        SyntheticSignalProvider("info-feed", ThreatDomain.INFO, seed=seed + 3),
        SyntheticSignalProvider("climate-feed", ThreatDomain.CLIMATE, seed=seed + 4),
    ]


def _build_openclaw_default_providers(args: argparse.Namespace) -> list[SignalProvider]:
    return [
        OpenClawSensor(
            name="cyber-osint",
            domain=ThreatDomain.CYBER,
            agent_id=args.sensor_agent_id,
            gateway_url=args.openclaw_gateway_url,
            openrouter_model=args.sensor_model,
            search_queries=[
                "critical CVE disclosed in last 24 hours",
                "active exploitation campaigns",
                "ransomware incidents this week",
            ],
            urls_to_monitor=[
                "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            ],
        ),
        OpenClawSensor(
            name="infra-osint",
            domain=ThreatDomain.INFRA,
            agent_id=args.sensor_agent_id,
            gateway_url=args.openclaw_gateway_url,
            openrouter_model=args.sensor_model,
            search_queries=[
                "critical infrastructure outage today",
                "industrial control system incident",
            ],
        ),
        OpenClawSensor(
            name="info-osint",
            domain=ThreatDomain.INFO,
            agent_id=args.sensor_agent_id,
            gateway_url=args.openclaw_gateway_url,
            openrouter_model=args.sensor_model,
            search_queries=[
                "coordinated disinformation campaign analysis",
                "bot network activity report",
            ],
        ),
        OpenClawSensor(
            name="climate-osint",
            domain=ThreatDomain.CLIMATE,
            agent_id=args.sensor_agent_id,
            gateway_url=args.openclaw_gateway_url,
            openrouter_model=args.sensor_model,
            search_queries=[
                "extreme weather affecting supply chain",
                "regional climate hazard warning update",
            ],
        ),
    ]


def _build_planner(
    args: argparse.Namespace,
    config: ResearchConfig,
    seed: int,
    scenario: Scenario | None = None,
) -> Planner:
    planner_mode = _resolve_planner_mode(args=args, scenario=scenario)
    if planner_mode == "openclaw":
        return OpenClawPlanner(
            config=config,
            agent_id=args.planner_agent_id,
            gateway_url=args.openclaw_gateway_url,
            openrouter_model=args.planner_model,
        )
    if planner_mode == "adversarial":
        adversarial_rate, enabled_plan_types = _resolve_adversarial_planner_config(
            scenario=scenario
        )
        return AdversarialPlanner(
            inner=MissionPlanner(config=config, seed=seed + 50),
            adversarial_rate=adversarial_rate,
            seed=seed + 150,
            enabled_plan_types=enabled_plan_types,
        )
    return MissionPlanner(config=config, seed=seed + 50)


def _build_effector(
    args: argparse.Namespace,
    config: ResearchConfig,
    seed: int,
) -> SimulationEffector | OpenClawEffector:
    if args.effector == "openclaw":
        return OpenClawEffector(
            config=config,
            agent_id=args.effector_agent_id,
            gateway_url=args.openclaw_gateway_url,
            openrouter_model=args.effector_model,
        )
    return SimulationEffector(config=config, seed=seed + 101)


def _build_control_policy(
    args: argparse.Namespace,
    config: ResearchConfig,
    planner_mode: str,
) -> ControlPolicy:
    name = getattr(args, "policy", "threshold")
    return _build_policy_by_name(
        name=name,
        args=args,
        config=config,
        planner_mode=planner_mode,
    )


def _build_policy_by_name(
    name: str,
    args: argparse.Namespace,
    config: ResearchConfig,
    planner_mode: str,
) -> ControlPolicy:
    if name == "threshold":
        return build_policy(name, threshold=config.review_threshold)
    if name == "adaptive":
        return build_policy(name, initial_threshold=config.review_threshold)
    if name == "debate" and planner_mode == "openclaw":
        return build_policy(
            name,
            use_openclaw=True,
            gateway_url=getattr(args, "openclaw_gateway_url", DEFAULT_GATEWAY_URL),
            openrouter_model=getattr(args, "effector_model", DEFAULT_OPENROUTER_MODEL),
        )
    return build_policy(name)


def _run_default(args: argparse.Namespace) -> str:
    providers = _build_default_providers(args)
    config = ResearchConfig()
    planner = _build_planner(args=args, config=config, seed=args.seed)
    planner_mode = _resolve_planner_mode(args=args, scenario=None)
    loop = WatchdogResearchLoop(
        providers=providers,
        config=config,
        seed=args.seed,
        planner=planner,
        effector=_build_effector(args=args, config=config, seed=args.seed),
        policy=_build_control_policy(args=args, config=config, planner_mode=planner_mode),
    )
    approved_steps = _parse_approved_steps(args.approved_steps)
    records = loop.run(steps=args.steps, approved_steps=approved_steps)
    report = records_to_markdown(records, adversarial_log=_extract_adversarial_log(planner))

    if args.output:
        write_markdown(Path(args.output), report)
    if args.json_output:
        write_json(Path(args.json_output), records)
    return report


def _run_scenario(args: argparse.Namespace) -> str:
    scenario = load_scenario(args.name, seed=args.seed)
    planner_mode = _resolve_planner_mode(args=args, scenario=scenario)
    planner = _build_planner(
        args=args,
        config=scenario.config,
        seed=scenario.seed,
        scenario=scenario,
    )
    loop = WatchdogResearchLoop(
        providers=scenario.providers,
        config=scenario.config,
        seed=scenario.seed,
        planner=planner,
        effector=_build_effector(args=args, config=scenario.config, seed=scenario.seed),
        policy=_build_control_policy(
            args=args,
            config=scenario.config,
            planner_mode=planner_mode,
        ),
    )
    records = loop.run(steps=scenario.steps, approved_steps=scenario.approved_steps)
    report = records_to_markdown(
        records,
        scenario_name=scenario.name,
        adversarial_log=_extract_adversarial_log(planner),
    )

    if args.output:
        write_markdown(Path(args.output), report)
    if hasattr(args, "json_output") and args.json_output:
        write_json(Path(args.json_output), records)
    return report


def _run_evaluate(args: argparse.Namespace) -> str:
    seeds = _parse_seeds(args.seeds, default_seed=args.seed)
    all_evals_by_scenario: dict[str, list[RunEvaluation]] = {
        name: [] for name in list_scenarios()
    }

    for name in list_scenarios():
        for seed in seeds:
            scenario = load_scenario(name, seed=seed)
            planner_mode = _resolve_planner_mode(args=args, scenario=scenario)
            planner = _build_planner(
                args=args,
                config=scenario.config,
                seed=scenario.seed,
                scenario=scenario,
            )
            loop = WatchdogResearchLoop(
                providers=scenario.providers,
                config=scenario.config,
                seed=scenario.seed,
                planner=planner,
                effector=_build_effector(
                    args=args,
                    config=scenario.config,
                    seed=scenario.seed,
                ),
                policy=_build_control_policy(
                    args=args,
                    config=scenario.config,
                    planner_mode=planner_mode,
                ),
            )
            records = loop.run(
                steps=scenario.steps, approved_steps=scenario.approved_steps
            )
            policy_name = records[0].policy_name if records else ""
            ev = evaluate_run(
                    [r.metrics for r in records],
                    scenario_name=scenario.name,
                    risk_trajectory=[r.risk_index for r in records],
                    policy_name=policy_name,
                    records=records,
                    adversarial_log=_extract_adversarial_log(planner),
                )
            all_evals_by_scenario[name].append(ev)

    if len(seeds) > 1:
        evaluations = [
            aggregate_run_evaluations(evals)
            for evals in all_evals_by_scenario.values()
        ]
        header = f"Aggregated over {len(seeds)} seeds: {seeds}\n\n"
    else:
        evaluations = [evals[0] for evals in all_evals_by_scenario.values()]
        header = ""

    report = header + compare_evaluations(evaluations)

    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(report, encoding="utf-8")
    return report


def _run_compare_policies(args: argparse.Namespace) -> str:
    seeds = _parse_seeds(args.seeds, default_seed=args.seed)
    raw_policies = args.policies.strip()
    policy_names = (
        [p.strip() for p in raw_policies.split(",") if p.strip()]
        if raw_policies
        else list(BUILTIN_POLICIES.keys())
    )

    evaluations: list[RunEvaluation] = []

    for pname in policy_names:
        per_seed_evals: list[RunEvaluation] = []
        for seed in seeds:
            scenario = load_scenario(args.name, seed=seed)
            planner_mode = _resolve_planner_mode(args=args, scenario=scenario)
            policy = _build_policy_by_name(
                name=pname,
                args=args,
                config=scenario.config,
                planner_mode=planner_mode,
            )
            planner = _build_planner(
                args=args,
                config=scenario.config,
                seed=scenario.seed,
                scenario=scenario,
            )
            loop = WatchdogResearchLoop(
                providers=scenario.providers,
                config=scenario.config,
                seed=scenario.seed,
                planner=planner,
                effector=_build_effector(
                    args=args, config=scenario.config, seed=scenario.seed,
                ),
                policy=policy,
            )
            records = loop.run(
                steps=scenario.steps, approved_steps=scenario.approved_steps,
            )
            policy_label = records[0].policy_name if records else pname
            ev = evaluate_run(
                [r.metrics for r in records],
                scenario_name=policy_label,
                risk_trajectory=[r.risk_index for r in records],
                policy_name=policy_label,
                records=records,
                adversarial_log=_extract_adversarial_log(planner),
            )
            per_seed_evals.append(ev)

        if len(seeds) > 1:
            evaluations.append(aggregate_run_evaluations(per_seed_evals))
        else:
            evaluations.append(per_seed_evals[0])

    header = f"Policy Comparison: {args.name} (seed{'s' if len(seeds) > 1 else ''}={seeds})\n\n"
    report = header + compare_evaluations(evaluations)

    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(report, encoding="utf-8")
    return report


def run(args: argparse.Namespace) -> str:
    if args.command == "scenario":
        return _run_scenario(args)
    if args.command == "evaluate":
        return _run_evaluate(args)
    if args.command == "compare-policies":
        return _run_compare_policies(args)
    if args.command == "list":
        return "\n".join(f"  - {name}" for name in list_scenarios())
    return _run_default(args)


def _resolve_planner_mode(
    args: argparse.Namespace,
    scenario: Scenario | None,
) -> str:
    planner = getattr(args, "planner", None)
    if isinstance(planner, str):
        return planner
    if scenario is not None:
        return scenario.planner_mode
    return "deterministic"


def _resolve_adversarial_planner_config(
    scenario: Scenario | None,
) -> tuple[float, tuple[str, ...]]:
    adversarial_rate = 0.30
    enabled_plan_types = DEFAULT_ADVERSARIAL_PLAN_TYPES
    if scenario is not None and scenario.planner_mode == "adversarial":
        raw_rate = scenario.planner_kwargs.get("adversarial_rate")
        if isinstance(raw_rate, (int, float)):
            adversarial_rate = float(raw_rate)

        raw_plan_types = scenario.planner_kwargs.get("enabled_plan_types")
        if isinstance(raw_plan_types, tuple) and all(
            isinstance(plan_type, str) for plan_type in raw_plan_types
        ):
            enabled_plan_types = raw_plan_types
    return adversarial_rate, enabled_plan_types


def _extract_adversarial_log(planner: Planner) -> dict[str, bool] | None:
    if isinstance(planner, AdversarialPlanner):
        return planner.adversarial_log
    return None


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    report = run(args)
    print(report)


if __name__ == "__main__":
    main()
