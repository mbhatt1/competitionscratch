"""Stateful taint-tracking guardrail example for local sandbox experiments."""

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


if __name__ == "__main__":
    # Test the guardrail
    guard = Guardrail()

    print("=" * 70)
    print("TAINT TRACKING GUARDRAIL TESTS")
    print("=" * 70)

    # Test 1: Normal operation without untrusted access
    print("\n[Test 1] Normal fs.delete from user (no taint):")
    context: dict[str, Any] = {"recent_sources": ["user", "file"]}
    decision = guard.decide("fs.delete", {"path": "temp.txt"}, context)
    print(f"  Result: {decision.action} - {decision.reason}")
    print(f"  Tainted: {guard.tainted}")

    # Test 2: Access untrusted source (should taint session)
    print("\n[Test 2] Access web.open (should taint session):")
    context = {"recent_sources": ["user", "web"]}
    decision = guard.decide("web.open", {"id": "demo"}, context)
    print(f"  Result: {decision.action} - {decision.reason}")
    print(f"  Tainted: {guard.tainted}")

    # Test 3: Try fs.delete in tainted session (should block)
    print("\n[Test 3] Try fs.delete in tainted session:")
    context = {"recent_sources": ["user", "web"]}
    decision = guard.decide("fs.delete", {"path": "secret.txt"}, context)
    print(f"  Result: {decision.action} - {decision.reason}")
    print(f"  Tainted: {guard.tainted}")

    # Test 4: Read operation in tainted session (should allow - read is safe)
    print("\n[Test 4] Try fs.read in tainted session:")
    context = {"recent_sources": ["user", "web"]}
    decision = guard.decide("fs.read", {"path": "readme.txt"}, context)
    print(f"  Result: {decision.action} - {decision.reason}")
    print(f"  Tainted: {guard.tainted}")

    # Test 5: User authorized operation (should clear taint)
    print("\n[Test 5] fs.delete with user authorization:")
    context = {"recent_sources": ["user"], "user_confirmed_safe": True}
    decision = guard.decide("fs.delete", {"path": "temp.txt"}, context)
    print(f"  Result: {decision.action} - {decision.reason}")
    print(f"  Tainted: {guard.tainted}")

    # Test 6: After taint cleared, dangerous op should work
    print("\n[Test 6] fs.delete after taint cleared:")
    context = {"recent_sources": ["user"]}
    decision = guard.decide("fs.delete", {"path": "temp.txt"}, context)
    print(f"  Result: {decision.action} - {decision.reason}")
    print(f"  Tainted: {guard.tainted}")

    # Test 7: Taint again and try shell.run
    print("\n[Test 7] Taint via email, then try shell.run:")
    guard.decide("email.read", {"id": "msg1"}, {"recent_sources": []})
    decision = guard.decide("shell.run", {"cmd": "echo test"}, {"recent_sources": []})
    print(f"  Result: {decision.action} - {decision.reason}")
    print(f"  Tainted: {guard.tainted}")

    # Test 8: Persistent taint across many operations
    print("\n[Test 8] Taint persists across 100 read operations:")
    guard.reset_session()
    guard.decide("web.open", {"id": "demo"}, {})
    for i in range(100):
        guard.decide("fs.read", {"path": f"file{i}.txt"}, {})
    decision = guard.decide("fs.delete", {"path": "secret.txt"}, {})
    print(f"  After 100 reads, tainted: {guard.tainted}")
    print(f"  Delete blocked: {decision.action == 'DENY'}")
    print(f"  Result: {decision.action}")

    print("\n" + "=" * 70)
    print("TESTS COMPLETE")
    print("=" * 70)
    print("\nKey Features Demonstrated:")
    print("  ✓ Persistent taint tracking across entire session")
    print("  ✓ Complete isolation (block dangerous ops when tainted)")
    print("  ✓ User override to clear taint")
    print("  ✓ Taint survives 100+ operations (no window limit)")
