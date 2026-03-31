from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class DecisionAction(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    CONFIRM = "CONFIRM"
    SANITIZE = "SANITIZE"


@dataclass(frozen=True, slots=True)
class Decision:
    action: DecisionAction
    reason: str = ""
    sanitized_args: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "action", DecisionAction(self.action))

    @staticmethod
    def allow(reason: str = "") -> "Decision":
        return Decision(DecisionAction.ALLOW, reason)

    @staticmethod
    def deny(reason: str = "") -> "Decision":
        return Decision(DecisionAction.DENY, reason)

    @staticmethod
    def confirm(reason: str = "") -> "Decision":
        return Decision(DecisionAction.CONFIRM, reason)

    @staticmethod
    def sanitize(sanitized_args: Mapping[str, Any], reason: str = "") -> "Decision":
        return Decision(DecisionAction.SANITIZE, reason, sanitized_args=sanitized_args)


class GuardrailBase:
    """Override decide() to implement a guardrail."""

    def decide(
        self, tool_name: str, tool_args: Mapping[str, Any], context: Mapping[str, Any]
    ) -> Decision:
        return Decision.allow("default allow")

    def snapshot_state(self) -> Any:
        """Capture guardrail state for env snapshot/restore flows."""
        return None

    def restore_state(self, snapshot: Any) -> None:
        """Restore guardrail state from a previous snapshot."""
        del snapshot
