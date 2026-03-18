"""Stateful taint-tracking guardrail example for local sandbox experiments."""

from collections.abc import Mapping
from typing import Any

from aicomp_sdk.guardrails.base import Decision, GuardrailBase


class Guardrail(GuardrailBase):
    """
    Taint tracking guardrail with session-level isolation.

    Once the agent accesses untrusted content (web/email), the entire session
    is marked as "tainted" and all dangerous operations are blocked until
    an explicit user command clears the taint.
    """

    def __init__(self):
        """Initialize the taint tracking guardrail."""
        super().__init__()

        # Session state
        self.tainted = False
        self.taint_source = None
        self.taint_operation_count = 0

        # Define dangerous operations that should be blocked when tainted
        self.dangerous_operations = {
            "fs.delete",  # File deletion
            "fs.write",  # File modification
            "shell.run",  # Command execution
            "http.post",  # Data exfiltration via HTTP
            "email.send",  # Data exfiltration via email
        }

        # Define untrusted sources
        self.untrusted_sources = {"web", "email"}

        # Track operations for debugging
        self.operation_log = []

    def decide(
        self, tool_name: str, tool_args: Mapping[str, Any], context: Mapping[str, Any]
    ) -> Decision:
        """
        Decide whether to allow or block a tool call based on taint state.

        Core logic:
        1. Check if current operation accesses untrusted source → taint session
        2. If session is tainted AND operation is dangerous → BLOCK
        3. If user explicitly authorized → allow and clear taint
        4. Otherwise allow

        Args:
            tool_name: Name of the tool being called
            tool_args: Arguments for the tool
            context: Context including recent_sources and user intent

        Returns:
            Decision to ALLOW or DENY the operation
        """
        # Log this operation
        self.operation_log.append(tool_name)
        self.taint_operation_count += 1

        # Check if this operation accesses an untrusted source
        current_source = self._get_source_type(tool_name)
        if current_source in self.untrusted_sources:
            if not self.tainted:
                self.tainted = True
                self.taint_source = current_source
                print(f"[TAINT] Session tainted by {current_source} access via {tool_name}")

        # Check for explicit user authorization to clear taint
        if context.get("user_confirmed_safe", False) or context.get("user_authorized", False):
            # User explicitly authorized this operation
            if self.tainted:
                print("[TAINT] User authorized operation - clearing taint")
                self.tainted = False
                self.taint_source = None
            return Decision.allow("User explicitly authorized this operation")

        # If session is tainted, check if operation is dangerous
        if self.tainted:
            if tool_name in self.dangerous_operations:
                # Block dangerous operation in tainted session
                reason = (
                    f"Blocked {tool_name} in tainted session "
                    f"(tainted by {self.taint_source} access)"
                )
                print(f"[TAINT] {reason}")
                return Decision.deny(reason)

        # Allow all other operations
        return Decision.allow("Operation allowed - session clean or operation safe")

    def _get_source_type(self, tool_name: str) -> str:
        """
        Determine the source type based on tool name.

        Args:
            tool_name: Name of the tool

        Returns:
            Source type: "web", "email", "file", or "user"
        """
        if tool_name.startswith("web."):
            return "web"
        elif tool_name.startswith("email."):
            return "email"
        elif tool_name.startswith("fs."):
            return "file"
        else:
            return "user"

    def reset_session(self):
        """Reset session state (for testing or new session)."""
        self.tainted = False
        self.taint_source = None
        self.operation_log = []
        self.taint_operation_count = 0
