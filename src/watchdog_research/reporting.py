from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from .evaluation import evaluate_run, format_evaluation
from .loop import CycleRecord


def records_to_markdown(
    records: list[CycleRecord],
    scenario_name: str = "",
    adversarial_log: dict[str, bool] | None = None,
) -> str:
    lines = ["# Exploratory Run Report", ""]
    lines.append("This report is simulation-only and intended for research review.")
    if scenario_name:
        lines.append(f"**Scenario:** {scenario_name}")
    lines.append("")

    for record in records:
        lines.append(f"## Step {record.step}")
        risk_d = record.metrics.risk_delta
        lines.append(f"- Risk index: `{record.risk_index:.3f}` (delta: `{risk_d:+.3f}`)")
        sig = record.metrics.signals_observed
        dom = record.metrics.domains_active
        lines.append(f"- Signals observed: `{sig}` across `{dom}` domain(s)")

        if not record.plan:
            lines.append("- Plan: none generated")
            lines.append("")
            continue

        lines.append(f"- Plan objective: {record.plan.objective}")
        pri = record.plan.priority
        cf = record.plan.counterfactual_score
        lines.append(f"- Priority: `{pri:.3f}` | Counterfactual: `{cf:.3f}`")
        lines.append(f"- Requires human review: `{record.plan.requires_human_review}`")

        if len(record.candidates) > 1:
            lines.append(f"- Candidate plans evaluated: `{len(record.candidates)}`")

        if record.result:
            lines.append(f"- Execution status: `{record.result.status.value}`")
            lines.append(f"- Estimated impact: `{record.result.estimated_impact:.3f}`")
            lines.append(f"- Side-effect risk: `{record.result.side_effect_risk:.3f}`")
            for entry in record.result.action_log[:3]:
                lines.append(f"- Effector trace: {entry}")
            if len(record.result.action_log) > 3:
                remaining = len(record.result.action_log) - 3
                lines.append(f"- Effector trace: ... and `{remaining}` more log entries")

        if record.verification:
            lines.append(
                f"- Outcome: `{record.verification.outcome.value}` | "
                f"Adjustment: `{record.verification.recommended_adjustment}` "
                f"(p={record.verification.success_probability:.3f})"
            )
        lines.append("")

    policy_name = records[0].policy_name if records else ""
    evaluation = evaluate_run(
        [r.metrics for r in records],
        scenario_name=scenario_name or "run",
        risk_trajectory=[r.risk_index for r in records],
        policy_name=policy_name,
        records=records,
        adversarial_log=adversarial_log,
    )
    lines.append("## Evaluation Summary")
    lines.append("")
    lines.append("```")
    lines.append(format_evaluation(evaluation))
    lines.append("```")
    lines.append("")

    return "\n".join(lines).strip() + "\n"


def write_markdown(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def write_json(path: Path, records: list[CycleRecord]) -> None:
    payload = [asdict(record) for record in records]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
