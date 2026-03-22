from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class ResearchConfig:
    """Tunable parameters for the exploratory mission loop.

    Every field is intentionally exposed so that systematic parameter sweeps
    and sensitivity analyses can be run over the full configuration surface.
    """

    # Planning
    review_threshold: float = 0.72
    max_actions_per_plan: int = 3
    candidate_plans: int = 3
    counterfactual_discount: float = 0.15

    # Effector simulation
    simulate_effector_noise: float = 0.08

    # Adaptation rates applied after verification
    stabilize_decay: float = 0.87
    escalation_growth: float = 1.08
    iteration_growth: float = 1.02
    passive_risk_decay: float = 0.9
    risk_blend_alpha: float = 0.65
