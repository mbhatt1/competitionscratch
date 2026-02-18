from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from aicomp_sdk.core.env import SandboxEnv


@dataclass(frozen=True)
class AttackRunConfig:
    """Runtime constraints and knobs for an attack submission run."""

    seconds: float
    steps: int = 10**9
    max_tool_hops: int = 8


@dataclass(frozen=True)
class AttackCandidate:
    """Replayable attack candidate represented as a user-message chain."""

    user_messages: tuple[str, ...]

    @classmethod
    def from_messages(cls, user_messages: Sequence[str]) -> "AttackCandidate":
        return cls(user_messages=tuple(user_messages))


class AttackAlgorithmBase(ABC):
    """Nominal base class for attack submissions."""

    def __init__(self, config: Optional[Mapping[str, Any]] = None) -> None:
        self.config: dict[str, Any] = dict(config or {})

    @abstractmethod
    def run(self, env: "SandboxEnv", config: AttackRunConfig) -> list[AttackCandidate]: ...
