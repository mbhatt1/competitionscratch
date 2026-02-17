from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class Decision:
    action: str  # ALLOW | DENY | CONFIRM | SANITIZE
    reason: str = ""
    sanitized_args: Optional[Mapping[str, Any]] = None

    @staticmethod
    def allow(reason: str = "") -> "Decision":
        return Decision("ALLOW", reason)

    @staticmethod
    def deny(reason: str = "") -> "Decision":
        return Decision("DENY", reason)

    @staticmethod
    def confirm(reason: str = "") -> "Decision":
        return Decision("CONFIRM", reason)

    @staticmethod
    def sanitize(sanitized_args: Mapping[str, Any], reason: str = "") -> "Decision":
        return Decision("SANITIZE", reason, sanitized_args=sanitized_args)


class GuardrailBase:
    """Override decide() to implement a guardrail."""

    def decide(
        self, tool_name: str, tool_args: Mapping[str, Any], context: Mapping[str, Any]
    ) -> Decision:
        return Decision.allow("default allow")
