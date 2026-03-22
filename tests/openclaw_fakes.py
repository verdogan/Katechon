from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar


@dataclass(slots=True)
class FakeExecuteResult:
    success: bool
    content: str = ""


class FakeAgent:
    def __init__(self, results: list[FakeExecuteResult]) -> None:
        self._results = list(results)
        self.prompts: list[str] = []

    async def execute(self, prompt: str) -> FakeExecuteResult:
        self.prompts.append(prompt)
        if self._results:
            return self._results.pop(0)
        return FakeExecuteResult(success=False, content="No mocked result available.")


class FakeConnection:
    def __init__(self, agent: FakeAgent, seen_agent_ids: list[str]) -> None:
        self._agent = agent
        self._seen_agent_ids = seen_agent_ids

    async def __aenter__(self) -> FakeConnection:
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> bool:
        return False

    def get_agent(self, agent_id: str) -> FakeAgent:
        self._seen_agent_ids.append(agent_id)
        return self._agent


class FakeOpenClawClient:
    gateway_urls: ClassVar[list[str]] = []
    agent_ids: ClassVar[list[str]] = []
    _agent: ClassVar[FakeAgent] = FakeAgent([])

    @classmethod
    def prime(cls, results: list[FakeExecuteResult]) -> None:
        cls.gateway_urls = []
        cls.agent_ids = []
        cls._agent = FakeAgent(results)

    @classmethod
    def connect(cls, **kwargs: str) -> FakeConnection:
        gateway_ws_url = kwargs.get("gateway_ws_url", "")
        cls.gateway_urls.append(gateway_ws_url)
        return FakeConnection(agent=cls._agent, seen_agent_ids=cls.agent_ids)

    @classmethod
    def recorded_prompts(cls) -> list[str]:
        return list(cls._agent.prompts)
