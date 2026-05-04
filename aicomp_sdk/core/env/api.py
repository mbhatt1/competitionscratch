from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final, Protocol, runtime_checkable

from aicomp_sdk.guardrails.base import GuardrailBase

DEFAULT_MAX_TOOL_HOPS: Final[int] = 8
MAX_USER_MESSAGE_CHARS: Final[int] = 2_000


def validate_interact_args(
    user_message: Any,
    max_tool_hops: Any,
    *,
    default_max_tool_hops: int | None = None,
    caller: str = "Env.interact",
) -> int | None:
    """Validate common AttackEnv.interact inputs and return resolved tool hops."""
    if not isinstance(user_message, str):
        raise TypeError(f"{caller} user_message must be a string")
    if len(user_message) > MAX_USER_MESSAGE_CHARS:
        raise ValueError(f"user_message exceeds max length ({MAX_USER_MESSAGE_CHARS} characters)")

    resolved_max_tool_hops = default_max_tool_hops if max_tool_hops is None else max_tool_hops
    if resolved_max_tool_hops is None:
        return None

    resolved_max_tool_hops = int(resolved_max_tool_hops)
    if resolved_max_tool_hops <= 0:
        raise ValueError("max_tool_hops must be positive")
    return resolved_max_tool_hops


class EnvSelection(StrEnum):
    SANDBOX = "sandbox"
    GYM = "gym"


def coerce_env_selection(value: str | EnvSelection) -> EnvSelection:
    try:
        return EnvSelection(value)
    except ValueError as err:
        raise ValueError(f"Unsupported env selection: {value}") from err


@dataclass(frozen=True)
class EnvInteractionResult:
    """Summary of one `interact` call and the counters it contributed."""

    seed: int
    total_tool_events: int = 0
    tool_events_added: int = 0
    agent_turns: int = 0
    successful_tool_calls: int = 0
    failed_tool_calls: int = 0
    agent_refused: bool = False


@dataclass
class EnvRunDiagnostics:
    """Aggregated counters for a sequence of environment interactions."""

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
    """Runtime protocol exposed to attack submissions during evaluator runs."""

    @property
    def seed(self) -> int:
        """Return the environment seed."""

    @seed.setter
    def seed(self, value: int) -> None:
        """Set the environment seed."""

    def reset(self, *args: Any, **kwargs: Any) -> Any:
        """Reset environment state."""

    def interact(self, user_message: str, max_tool_hops: int | None = None) -> EnvInteractionResult:
        """Run one user interaction turn."""

    def export_trace_dict(self) -> dict[str, Any]:
        """Return the trace as a serializable dictionary."""

    def snapshot(self) -> Any:
        """Capture a restorable environment snapshot."""

    def restore(self, snapshot: Any) -> None:
        """Restore a snapshot captured by snapshot()."""


@runtime_checkable
class _HarnessAttackEnvProtocol(AttackEnvProtocol, Protocol):
    """Internal protocol for evaluator harnesses and direct SDK environments."""

    @property
    def trace(self) -> Any:
        """Return the current trace object."""

    @property
    def tools(self) -> Any:
        """Return the tool suite bound to this environment."""

    @property
    def guardrail(self) -> GuardrailBase:
        """Return the active guardrail."""


class DiagnosticsEnv:
    """Proxy that forwards env calls while accumulating run diagnostics."""

    def __init__(self, inner: _HarnessAttackEnvProtocol) -> None:
        self._inner = inner
        self.run_diagnostics = EnvRunDiagnostics()

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

    def interact(self, user_message: str, max_tool_hops: int | None = None) -> EnvInteractionResult:
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
