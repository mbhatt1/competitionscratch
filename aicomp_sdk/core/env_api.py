from __future__ import annotations

from collections.abc import Mapping
from enum import Enum
from typing import Any, Protocol, runtime_checkable

from aicomp_sdk.guardrails.base import GuardrailBase

DEFAULT_MAX_TOOL_HOPS = 8
MAX_USER_MESSAGE_CHARS = 2_000


class EnvSelection(str, Enum):
    SANDBOX = "sandbox"
    GYM = "gym"

    def __str__(self) -> str:
        return self.value


def parse_env_selection(value: str | EnvSelection) -> EnvSelection:
    if isinstance(value, EnvSelection):
        return value
    try:
        return EnvSelection(value)
    except ValueError as err:
        raise ValueError(f"Unsupported env selection: {value}") from err


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
    ) -> dict[str, Any]:
        pass

    def export_trace_dict(self) -> dict[str, Any]:
        pass

    def snapshot(self) -> dict[str, Any]:
        pass

    def restore(self, snapshot: Mapping[str, Any]) -> None:
        pass
