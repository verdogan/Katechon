"""Exploratory active-defense watchdog research package."""

from .adversarial_planner import AdversarialPlanner
from .config import ResearchConfig
from .control_policies import (
    AdaptiveThreshold,
    ConstitutionalCheck,
    ControlPolicy,
    MultiAgentDebate,
    ThresholdGating,
    build_policy,
)
from .loop import WatchdogResearchLoop
from .openclaw_effector import OpenClawEffector
from .openclaw_planner import OpenClawPlanner
from .openclaw_sensors import OpenClawSensor
from .scenarios import list_scenarios, load_scenario

__all__ = [
    "AdaptiveThreshold",
    "AdversarialPlanner",
    "ConstitutionalCheck",
    "ControlPolicy",
    "MultiAgentDebate",
    "OpenClawEffector",
    "OpenClawPlanner",
    "OpenClawSensor",
    "ResearchConfig",
    "ThresholdGating",
    "WatchdogResearchLoop",
    "build_policy",
    "list_scenarios",
    "load_scenario",
]
