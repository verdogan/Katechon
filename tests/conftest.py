from __future__ import annotations

import pytest

from watchdog_research.config import ResearchConfig
from watchdog_research.domain import ThreatDomain, ThreatSignal


class FixedProvider:
    """Deterministic provider that always emits one signal per tick."""

    def __init__(
        self,
        severity: float,
        confidence: float,
        domain: ThreatDomain,
        name: str = "fixed-provider",
    ) -> None:
        self.name = name
        self._severity = severity
        self._confidence = confidence
        self._domain = domain

    def collect(self, tick: int) -> list[ThreatSignal]:
        return [
            ThreatSignal(
                source=self.name,
                domain=self._domain,
                severity=self._severity,
                confidence=self._confidence,
                summary=f"tick={tick}",
            )
        ]


class EmptyProvider:
    """Provider that never emits signals."""

    name = "empty-provider"

    def collect(self, tick: int) -> list[ThreatSignal]:
        return []


@pytest.fixture
def high_severity_provider() -> FixedProvider:
    return FixedProvider(severity=0.95, confidence=0.95, domain=ThreatDomain.CYBER)


@pytest.fixture
def low_severity_provider() -> FixedProvider:
    return FixedProvider(severity=0.3, confidence=0.4, domain=ThreatDomain.INFO)


@pytest.fixture
def default_config() -> ResearchConfig:
    return ResearchConfig()


@pytest.fixture
def strict_review_config() -> ResearchConfig:
    return ResearchConfig(review_threshold=0.70)
