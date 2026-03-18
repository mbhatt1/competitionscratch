"""Persistent-taint guardrail example for prompt-injection-style attacks."""

from __future__ import annotations

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
