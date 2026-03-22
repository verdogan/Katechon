from __future__ import annotations

import pytest

from watchdog_research.config import ResearchConfig
from watchdog_research.domain import ThreatDomain, ThreatSignal, WorldState
from watchdog_research.planner import MissionPlanner


@pytest.fixture
def planner() -> MissionPlanner:
    return MissionPlanner(ResearchConfig(candidate_plans=3), seed=42)


class TestCandidateGeneration:
    def test_generates_candidates_for_each_domain(self, planner: MissionPlanner) -> None:
        state = WorldState()
        state.ingest([
            ThreatSignal("a", ThreatDomain.CYBER, 0.9, 0.9, "high"),
            ThreatSignal("b", ThreatDomain.INFRA, 0.7, 0.8, "medium"),
            ThreatSignal("c", ThreatDomain.CLIMATE, 0.5, 0.6, "low"),
        ])

        candidates = planner.create_candidates(state)

        assert len(candidates) == 3
        domains = {c.actions[0].target for c in candidates}
        assert "soc" in domains
        assert "infrastructure" in domains
        assert "climate-ops" in domains

    def test_no_candidates_without_threats(self, planner: MissionPlanner) -> None:
        state = WorldState()
        state.ingest([])

        candidates = planner.create_candidates(state)

        assert candidates == []

    def test_candidates_capped_by_config(self) -> None:
        config = ResearchConfig(candidate_plans=1)
        planner = MissionPlanner(config, seed=42)
        state = WorldState()
        state.ingest([
            ThreatSignal("a", ThreatDomain.CYBER, 0.9, 0.9, "high"),
            ThreatSignal("b", ThreatDomain.INFRA, 0.7, 0.8, "medium"),
        ])

        candidates = planner.create_candidates(state)

        assert len(candidates) == 1


class TestCounterfactualScoring:
    def test_higher_severity_gets_higher_counterfactual(self, planner: MissionPlanner) -> None:
        state = WorldState()
        state.ingest([
            ThreatSignal("a", ThreatDomain.CYBER, 0.95, 0.95, "high"),
            ThreatSignal("b", ThreatDomain.INFO, 0.3, 0.3, "low"),
        ])

        candidates = planner.create_candidates(state)

        high = next(c for c in candidates if "cyber" in c.objective)
        low = next(c for c in candidates if "information" in c.objective)
        assert high.counterfactual_score > low.counterfactual_score

    def test_counterfactual_scores_are_bounded(self, planner: MissionPlanner) -> None:
        state = WorldState()
        state.ingest([
            ThreatSignal("x", ThreatDomain.BIO, 1.0, 1.0, "max"),
        ])

        candidates = planner.create_candidates(state)

        for c in candidates:
            assert 0.0 <= c.counterfactual_score <= 1.0


class TestPlanRanking:
    def test_best_candidate_is_selected_as_plan(self, planner: MissionPlanner) -> None:
        state = WorldState()
        state.ingest([
            ThreatSignal("a", ThreatDomain.CYBER, 0.95, 0.95, "high"),
            ThreatSignal("b", ThreatDomain.CLIMATE, 0.4, 0.4, "low"),
        ])

        plan = planner.create_plan(state)
        candidates = planner.create_candidates(state)

        assert plan is not None
        assert plan.objective == candidates[0].objective

    def test_grounded_metadata_produces_asset_specific_plan(self, planner: MissionPlanner) -> None:
        state = WorldState()
        state.ingest([
            ThreatSignal(
                "cyber-feed",
                ThreatDomain.CYBER,
                0.95,
                0.95,
                "high",
                metadata={
                    "asset": "payments-api-prod",
                    "location": "us-east-1 payment cluster",
                    "owner": "platform-security",
                    "response_team": "soc",
                    "monitoring_surface": "payments-api-prod telemetry",
                    "dependency_hint": "card settlement gateway",
                    "incident_type": "credential stuffing burst",
                    "indicator": "impossible-travel login spike",
                },
            ),
        ])

        plan = planner.create_plan(state)

        assert plan is not None
        assert "payments-api-prod" in plan.objective
        assert "credential stuffing burst" in plan.objective
        assert "impossible-travel login spike" in plan.rationale
        assert any("payments-api-prod" in action.description for action in plan.actions)
        assert any(action.target == "payments-api-prod" for action in plan.actions)
