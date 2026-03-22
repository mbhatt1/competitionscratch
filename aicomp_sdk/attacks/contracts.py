from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Self

from aicomp_sdk.core.env.api import DEFAULT_MAX_TOOL_HOPS, AttackEnvProtocol


@dataclass(frozen=True)
class AttackRunConfig:
    """Runtime constraints and knobs for an attack submission run.

    ``time_budget_s`` is the wall-clock budget for the full attack run.
    ``max_steps`` caps the attack algorithm's outer-loop search steps.
    ``max_tool_hops`` caps the blue-agent/tool loop for each attacker message.
    """

    time_budget_s: float = 30.0
    max_steps: int = 10**9
    max_tool_hops: int = DEFAULT_MAX_TOOL_HOPS


@dataclass(frozen=True)
class AttackCandidate:
    """Replayable attack candidate represented as a user-message chain."""

    user_messages: tuple[str, ...]

    @classmethod
    def from_messages(cls, user_messages: Sequence[str]) -> Self:
        return cls(user_messages=tuple(user_messages))


class AttackAlgorithmBase(ABC):
    """Nominal base class for attack submissions."""

    def __init__(self, config: Mapping[str, Any] | None = None) -> None:
        self.config: dict[str, Any] = dict(config or {})

    @abstractmethod
    def run(self, env: AttackEnvProtocol, config: AttackRunConfig) -> list[AttackCandidate]:
        pass
