from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol, Union, runtime_checkable

from aicomp_sdk.guardrails.base import GuardrailBase

DEFAULT_MAX_TOOL_HOPS = 8
MAX_USER_MESSAGE_CHARS = 2_000


class EnvSelection(str, Enum):
    SANDBOX = "sandbox"
    GYM = "gym"

    def __str__(self) -> str:
        return self.value


def parse_env_selection(value: Union[str, EnvSelection]) -> EnvSelection:
    if isinstance(value, EnvSelection):
        return value
    try:
        return EnvSelection(value)
    except ValueError as err:
        raise ValueError(f"Unsupported env selection: {value}") from err


@dataclass(frozen=True)
class EnvInteractionResult:
    seed: int
    total_tool_events: int = 0
    tool_events_added: int = 0
    agent_turns: int = 0
    successful_tool_calls: int = 0
    failed_tool_calls: int = 0
    agent_refused: bool = False


@dataclass
class RunDiagnostics:
    interactions: int = 0
    agent_turns: int = 0
    tool_calls: int = 0
    successful_tool_calls: int = 0
    failed_tool_calls: int = 0
    agent_refusals: int = 0

    def record(self, result: EnvInteractionResult) -> None:
        self.interactions += 1
        self.agent_turns += result.agent_turns
        self.tool_calls += result.tool_events_added
        self.successful_tool_calls += result.successful_tool_calls
        self.failed_tool_calls += result.failed_tool_calls
        self.agent_refusals += int(result.agent_refused)


@runtime_checkable
class AttackEnvProtocol(Protocol):
    seed: int
    trace: Any
    tools: Any
    guardrail: GuardrailBase

    def reset(self, *args: Any, **kwargs: Any) -> Any:
        pass

    def interact(
        self, user_message: str, max_tool_hops: int = DEFAULT_MAX_TOOL_HOPS
    ) -> EnvInteractionResult:
        pass

    def export_trace_dict(self) -> dict[str, Any]:
        pass

    def snapshot(self) -> Any:
        pass

    def restore(self, snapshot: Any) -> None:
        pass


class DiagnosticsEnv:
    def __init__(self, inner: AttackEnvProtocol) -> None:
        self._inner = inner
        self.run_diagnostics = RunDiagnostics()

    @property
    def seed(self) -> int:
        return self._inner.seed

    @seed.setter
    def seed(self, value: int) -> None:
        self._inner.seed = int(value)

    @property
    def trace(self) -> Any:
        return self._inner.trace

    @property
    def tools(self) -> Any:
        return self._inner.tools

    @property
    def guardrail(self) -> GuardrailBase:
        return self._inner.guardrail

    def reset(self, *args: Any, **kwargs: Any) -> Any:
        return self._inner.reset(*args, **kwargs)

    def interact(
        self, user_message: str, max_tool_hops: int = DEFAULT_MAX_TOOL_HOPS
    ) -> EnvInteractionResult:
        result = self._inner.interact(user_message, max_tool_hops=max_tool_hops)
        self.run_diagnostics.record(result)
        return result

    def export_trace_dict(self) -> dict[str, Any]:
        return self._inner.export_trace_dict()

    def snapshot(self) -> Any:
        return self._inner.snapshot()

    def restore(self, snapshot: Any) -> None:
        self._inner.restore(snapshot)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)
