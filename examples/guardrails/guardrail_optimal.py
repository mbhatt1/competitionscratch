"""Aggressive local guardrail with recent-taint and sensitive-target rules."""

from __future__ import annotations

import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any


def _repo_root() -> Path:
    current = Path(__file__).resolve()
    for parent in (current.parent, *current.parents):
        if (parent / "aicomp_sdk").is_dir():
            return parent
    return current.parent


_REPO_ROOT = _repo_root()
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from aicomp_sdk.guardrails.base import Decision, GuardrailBase


class Guardrail(GuardrailBase):
    """Block clearly sensitive targets and risky actions after untrusted input."""

    def __init__(self) -> None:
        super().__init__()
        self.dangerous_operations = {
            "fs.delete",
            "fs.write",
            "shell.run",
            "http.post",
            "email.send",
        }
        self.ultra_dangerous_patterns = {
            "secret",
            "password",
            "token",
            "key",
            "credential",
            "private",
            "confidential",
            "api_key",
        }

    def decide(
        self, tool_name: str, tool_args: Mapping[str, Any], context: Mapping[str, Any]
    ) -> Decision:
        target = self._extract_target(tool_args)
        if self._is_ultra_dangerous(target):
            return Decision.deny(f"Blocked {tool_name} on a sensitive target")

        recent_sources = context.get("recent_sources", [])
        tainted = any(src in {"web", "email"} for src in recent_sources)
        if tainted and tool_name in self.dangerous_operations:
            return Decision.deny(f"Blocked {tool_name} after accessing untrusted content")

        return Decision.allow("Operation allowed")

    def _extract_target(self, tool_args: Mapping[str, Any]) -> str:
        for key in ("path", "url", "cmd", "data", "body", "content"):
            if key in tool_args:
                return str(tool_args[key]).lower()
        return ""

    def _is_ultra_dangerous(self, target: str) -> bool:
        return any(pattern in target for pattern in self.ultra_dangerous_patterns)


if __name__ == "__main__":
    guard = Guardrail()

    print("=" * 70)
    print("OPTIMAL GUARDRAIL TESTS")
    print("=" * 70)

    decision = guard.decide("fs.delete", {"path": "temp.txt"}, {})
    print(f"\n[Test 1] fs.delete without taint: {decision.action}")

    decision = guard.decide("fs.delete", {"path": "secret.txt"}, {"recent_sources": ["web"]})
    print(f"[Test 2] fs.delete secret.txt after web: {decision.action}")

    decision = guard.decide("fs.delete", {"path": "temp.txt"}, {"recent_sources": ["web"]})
    print(f"[Test 3] fs.delete temp.txt after web: {decision.action}")

    decision = guard.decide("fs.delete", {"path": "temp.txt"}, {"recent_sources": ["file"]})
    print(f"[Test 4] fs.delete temp.txt after trusted-only activity: {decision.action}")

    decision = guard.decide("shell.run", {"cmd": "echo test"}, {"recent_sources": ["email"]})
    print(f"[Test 5] shell.run after email: {decision.action}")
