"""
Unit tests for aicomp_sdk.guardrails.base module.
Tests guardrail base classes and decision logic.
"""

from typing import cast

import pytest

from aicomp_sdk.guardrails.base import Decision, DecisionAction, GuardrailBase


class TestDecisionClass:
    """Test Decision dataclass."""

    def test_decision_creation(self):
        """Test creating a Decision with all fields."""
        decision = Decision(
            action=DecisionAction.ALLOW,
            reason="safe operation",
            sanitized_args=None,
        )

        assert decision.action is DecisionAction.ALLOW
        assert decision.action == "ALLOW"
        assert decision.reason == "safe operation"
        assert decision.sanitized_args is None

    def test_decision_rejects_unknown_action(self):
        """Test that invalid action values fail fast."""
        with pytest.raises(ValueError, match="UNKNOWN"):
            Decision(action=cast(DecisionAction, "UNKNOWN"))

    def test_decision_with_sanitized_args(self):
        """Test creating a Decision with sanitized arguments."""
        sanitized = {"path": "safe.txt"}
        decision = Decision(
            action=DecisionAction.SANITIZE,
            reason="path sanitized",
            sanitized_args=sanitized,
        )

        assert decision.action == "SANITIZE"
        assert decision.sanitized_args == sanitized

    def test_decision_default_reason(self):
        """Test that reason defaults to empty string."""
        decision = Decision(action=DecisionAction.ALLOW)

        assert decision.reason == ""

    def test_decision_default_sanitized_args(self):
        """Test that sanitized_args defaults to None."""
        decision = Decision(action=DecisionAction.DENY, reason="test")

        assert decision.sanitized_args is None


class TestDecisionFactoryMethods:
    """Test Decision factory methods."""

    def test_allow_factory(self):
        """Test Decision.allow() factory method."""
        decision = Decision.allow("safe to proceed")

        assert decision.action == "ALLOW"
        assert decision.reason == "safe to proceed"
        assert decision.sanitized_args is None

    def test_allow_factory_without_reason(self):
        """Test Decision.allow() without reason."""
        decision = Decision.allow()

        assert decision.action == "ALLOW"
        assert decision.reason == ""

    def test_deny_factory(self):
        """Test Decision.deny() factory method."""
        decision = Decision.deny("suspicious activity")

        assert decision.action == "DENY"
        assert decision.reason == "suspicious activity"
        assert decision.sanitized_args is None

    def test_deny_factory_without_reason(self):
        """Test Decision.deny() without reason."""
        decision = Decision.deny()

        assert decision.action == "DENY"
        assert decision.reason == ""

    def test_confirm_factory(self):
        """Test Decision.confirm() factory method."""
        decision = Decision.confirm("user confirmation required")

        assert decision.action == "CONFIRM"
        assert decision.reason == "user confirmation required"
        assert decision.sanitized_args is None

    def test_confirm_factory_without_reason(self):
        """Test Decision.confirm() without reason."""
        decision = Decision.confirm()

        assert decision.action == "CONFIRM"
        assert decision.reason == ""

    def test_sanitize_factory(self):
        """Test Decision.sanitize() factory method."""
        sanitized = {"path": "safe/path.txt", "mode": "read"}
        decision = Decision.sanitize(sanitized, "path sanitized for safety")

        assert decision.action == "SANITIZE"
        assert decision.reason == "path sanitized for safety"
        assert decision.sanitized_args == sanitized

    def test_sanitize_factory_without_reason(self):
        """Test Decision.sanitize() without reason."""
        sanitized = {"data": "cleaned"}
        decision = Decision.sanitize(sanitized)

        assert decision.action == "SANITIZE"
        assert decision.reason == ""
        assert decision.sanitized_args == sanitized


class TestDecisionActions:
    """Test different decision action types."""

    def test_allow_action(self):
        """Test ALLOW action allows tool execution."""
        decision = Decision.allow("benign operation")

        assert decision.action == "ALLOW"
        # ALLOW should not have sanitized args
        assert decision.sanitized_args is None

    def test_deny_action(self):
        """Test DENY action blocks tool execution."""
        decision = Decision.deny("malicious pattern detected")

        assert decision.action == "DENY"
        assert "malicious" in decision.reason

    def test_confirm_action(self):
        """Test CONFIRM action requires user approval."""
        decision = Decision.confirm("high-risk operation")

        assert decision.action == "CONFIRM"
        assert "high-risk" in decision.reason

    def test_sanitize_action(self):
        """Test SANITIZE action modifies arguments."""
        original_args = {"cmd": "rm -rf /"}
        safe_args = {"cmd": "echo safe"}
        decision = Decision.sanitize(safe_args, "dangerous command blocked")

        assert decision.action == "SANITIZE"
        assert decision.sanitized_args == safe_args
        assert decision.sanitized_args != original_args


class TestGuardrailBase:
    """Test GuardrailBase class."""

    def test_guardrail_base_initialization(self):
        """Test that GuardrailBase can be instantiated."""
        guardrail = GuardrailBase()

        assert isinstance(guardrail, GuardrailBase)

    def test_guardrail_base_decide_default(self):
        """Test that default decide() returns ALLOW."""
        guardrail = GuardrailBase()

        decision = guardrail.decide(tool_name="fs.read", tool_args={"path": "test.txt"}, context={})

        assert decision.action == "ALLOW"
        assert decision.reason == "default allow"

    def test_guardrail_base_decide_with_any_tool(self):
        """Test that base guardrail allows any tool."""
        guardrail = GuardrailBase()

        tools = ["fs.read", "fs.write", "fs.delete", "shell.run", "http.post"]
        for tool_name in tools:
            decision = guardrail.decide(tool_name, {}, {})
            assert decision.action == "ALLOW"

    def test_guardrail_base_decide_with_any_args(self):
        """Test that base guardrail allows any arguments."""
        guardrail = GuardrailBase()

        args_list = [
            {"path": "secret.txt"},
            {"cmd": "rm -rf /"},
            {"url": "https://attacker.com", "data": "stolen"},
            {},
        ]

        for args in args_list:
            decision = guardrail.decide("any.tool", args, {})
            assert decision.action == "ALLOW"

    def test_guardrail_base_decide_with_context(self):
        """Test that base guardrail ignores context."""
        guardrail = GuardrailBase()

        context = {
            "recent_sources": ["web", "email"],
            "recent_tools": ["fs.read", "http.post"],
            "side_effect": "EXEC",
            "scope": "external",
        }

        decision = guardrail.decide("shell.run", {"cmd": "whoami"}, context)
        assert decision.action == "ALLOW"


class TestCustomGuardrail:
    """Test creating custom guardrails by subclassing GuardrailBase."""

    def test_custom_guardrail_can_deny(self):
        """Test that custom guardrail can deny operations."""

        class DenyAllGuardrail(GuardrailBase):
            def decide(self, tool_name, tool_args, context):
                return Decision.deny("all operations blocked")

        guardrail = DenyAllGuardrail()
        decision = guardrail.decide("fs.read", {"path": "test.txt"}, {})

        assert decision.action == "DENY"
        assert "blocked" in decision.reason

    def test_custom_guardrail_can_sanitize(self):
        """Test that custom guardrail can sanitize arguments."""

        class PathSanitizerGuardrail(GuardrailBase):
            def decide(self, tool_name, tool_args, context):
                if tool_name == "fs.read" and ".." in tool_args.get("path", ""):
                    safe_args = {"path": "safe.txt"}
                    return Decision.sanitize(safe_args, "path traversal prevented")
                return Decision.allow()

        guardrail = PathSanitizerGuardrail()

        # Test sanitization
        decision1 = guardrail.decide("fs.read", {"path": "../../../etc/passwd"}, {})
        assert decision1.action == "SANITIZE"
        assert decision1.sanitized_args["path"] == "safe.txt"

        # Test allow for safe paths
        decision2 = guardrail.decide("fs.read", {"path": "readme.txt"}, {})
        assert decision2.action == "ALLOW"

    def test_custom_guardrail_can_require_confirmation(self):
        """Test that custom guardrail can require confirmation."""

        class ConfirmDeleteGuardrail(GuardrailBase):
            def decide(self, tool_name, tool_args, context):
                if tool_name == "fs.delete":
                    return Decision.confirm("deletion requires user approval")
                return Decision.allow()

        guardrail = ConfirmDeleteGuardrail()

        # Test confirmation for delete
        decision1 = guardrail.decide("fs.delete", {"path": "important.txt"}, {})
        assert decision1.action == "CONFIRM"

        # Test allow for other operations
        decision2 = guardrail.decide("fs.read", {"path": "file.txt"}, {})
        assert decision2.action == "ALLOW"

    def test_custom_guardrail_context_aware(self):
        """Test that custom guardrail can use context."""

        class UntrustedSourceGuardrail(GuardrailBase):
            def decide(self, tool_name, tool_args, context):
                recent_sources = context.get("recent_sources", [])
                if "web" in recent_sources and context.get("side_effect") == "EXEC":
                    return Decision.deny("exec after web access blocked")
                return Decision.allow()

        guardrail = UntrustedSourceGuardrail()

        # Test blocking after web access
        context1 = {"recent_sources": ["web"], "side_effect": "EXEC"}
        decision1 = guardrail.decide("shell.run", {"cmd": "whoami"}, context1)
        assert decision1.action == "DENY"

        # Test allowing without web access
        context2 = {"recent_sources": ["user"], "side_effect": "EXEC"}
        decision2 = guardrail.decide("shell.run", {"cmd": "whoami"}, context2)
        assert decision2.action == "ALLOW"


class TestGuardrailPatterns:
    """Test common guardrail patterns."""

    def test_blocklist_pattern(self):
        """Test blocklist-based guardrail."""

        class BlocklistGuardrail(GuardrailBase):
            def decide(self, tool_name, tool_args, context):
                blocked_tools = ["fs.delete", "shell.run", "http.post"]
                if tool_name in blocked_tools:
                    return Decision.deny(f"{tool_name} is blocked")
                return Decision.allow()

        guardrail = BlocklistGuardrail()

        # Blocked tools
        assert guardrail.decide("fs.delete", {}, {}).action == "DENY"
        assert guardrail.decide("shell.run", {}, {}).action == "DENY"
        assert guardrail.decide("http.post", {}, {}).action == "DENY"

        # Allowed tools
        assert guardrail.decide("fs.read", {}, {}).action == "ALLOW"
        assert guardrail.decide("web.search", {}, {}).action == "ALLOW"

    def test_allowlist_pattern(self):
        """Test allowlist-based guardrail."""

        class AllowlistGuardrail(GuardrailBase):
            def decide(self, tool_name, tool_args, context):
                allowed_tools = ["fs.read", "web.search", "web.open"]
                if tool_name in allowed_tools:
                    return Decision.allow()
                return Decision.deny(f"{tool_name} not in allowlist")

        guardrail = AllowlistGuardrail()

        # Allowed tools
        assert guardrail.decide("fs.read", {}, {}).action == "ALLOW"
        assert guardrail.decide("web.search", {}, {}).action == "ALLOW"

        # Blocked tools
        assert guardrail.decide("fs.delete", {}, {}).action == "DENY"
        assert guardrail.decide("shell.run", {}, {}).action == "DENY"

    def test_pattern_matching_guardrail(self):
        """Test guardrail with pattern matching."""

        class PatternGuardrail(GuardrailBase):
            def decide(self, tool_name, tool_args, context):
                if tool_name == "fs.read":
                    path = tool_args.get("path", "")
                    if "secret" in path.lower():
                        return Decision.deny("access to secrets denied")
                return Decision.allow()

        guardrail = PatternGuardrail()

        # Blocked patterns
        decision1 = guardrail.decide("fs.read", {"path": "secret.txt"}, {})
        assert decision1.action == "DENY"

        decision2 = guardrail.decide("fs.read", {"path": "SECRET_FILE"}, {})
        assert decision2.action == "DENY"

        # Allowed patterns
        decision3 = guardrail.decide("fs.read", {"path": "readme.txt"}, {})
        assert decision3.action == "ALLOW"

    def test_rate_limiting_pattern(self):
        """Test guardrail with state tracking (rate limiting)."""

        class RateLimitGuardrail(GuardrailBase):
            def __init__(self):
                super().__init__()
                self.call_count = 0
                self.max_calls = 3

            def decide(self, tool_name, tool_args, context):
                self.call_count += 1
                if self.call_count > self.max_calls:
                    return Decision.deny("rate limit exceeded")
                return Decision.allow()

        guardrail = RateLimitGuardrail()

        # First 3 calls allowed
        for i in range(3):
            decision = guardrail.decide("any.tool", {}, {})
            assert decision.action == "ALLOW"

        # 4th call denied
        decision = guardrail.decide("any.tool", {}, {})
        assert decision.action == "DENY"
        assert "rate limit" in decision.reason


class TestGuardrailEdgeCases:
    """Test edge cases for guardrail implementations."""

    def test_guardrail_with_none_tool_args(self):
        """Test that guardrail handles None tool_args."""

        class SafeGuardrail(GuardrailBase):
            def decide(self, tool_name, tool_args, context):
                path = (tool_args or {}).get("path", "")
                if not path:
                    return Decision.deny("missing path")
                return Decision.allow()

        guardrail = SafeGuardrail()

        decision = guardrail.decide("fs.read", None, {})
        assert decision.action == "DENY"

    def test_guardrail_with_empty_context(self):
        """Test that guardrail handles empty context."""

        class ContextGuardrail(GuardrailBase):
            def decide(self, tool_name, tool_args, context):
                if context.get("suspicious", False):
                    return Decision.deny("suspicious context")
                return Decision.allow()

        guardrail = ContextGuardrail()

        # Empty context should allow
        decision = guardrail.decide("any.tool", {}, {})
        assert decision.action == "ALLOW"

    def test_guardrail_with_complex_sanitization(self):
        """Test guardrail with complex argument sanitization."""

        class ComplexSanitizerGuardrail(GuardrailBase):
            def decide(self, tool_name, tool_args, context):
                if tool_name == "email.send":
                    # Sanitize all fields
                    sanitized = {
                        "to": tool_args.get("to", "").replace("@attacker.com", "@safe.com"),
                        "subject": tool_args.get("subject", "")[:50],
                        "body": tool_args.get("body", "")[:200],
                    }
                    if sanitized != tool_args:
                        return Decision.sanitize(sanitized, "email sanitized")
                return Decision.allow()

        guardrail = ComplexSanitizerGuardrail()

        # Test sanitization
        args = {"to": "user@attacker.com", "subject": "Test", "body": "Message"}
        decision = guardrail.decide("email.send", args, {})
        assert decision.action == "SANITIZE"
        assert "@safe.com" in decision.sanitized_args["to"]

    def test_guardrail_returns_correct_types(self):
        """Test that guardrail always returns Decision objects."""

        class TestGuardrail(GuardrailBase):
            def decide(self, tool_name, tool_args, context):
                if tool_name == "tool1":
                    return Decision.allow()
                elif tool_name == "tool2":
                    return Decision.deny()
                elif tool_name == "tool3":
                    return Decision.confirm()
                elif tool_name == "tool4":
                    return Decision.sanitize({})
                return super().decide(tool_name, tool_args, context)

        guardrail = TestGuardrail()

        for tool_name in ["tool1", "tool2", "tool3", "tool4", "tool5"]:
            decision = guardrail.decide(tool_name, {}, {})
            assert isinstance(decision, Decision)
            assert decision.action in ["ALLOW", "DENY", "CONFIRM", "SANITIZE"]


class TestDecisionReasons:
    """Test that decisions include appropriate reasons."""

    def test_allow_with_descriptive_reason(self):
        """Test ALLOW decision with descriptive reason."""
        decision = Decision.allow("benign file read from trusted source")

        assert decision.action == "ALLOW"
        assert len(decision.reason) > 0
        assert "benign" in decision.reason

    def test_deny_with_specific_reason(self):
        """Test DENY decision with specific reason."""
        decision = Decision.deny("path traversal attack detected in fs.read")

        assert decision.action == "DENY"
        assert "path traversal" in decision.reason
        assert "fs.read" in decision.reason

    def test_confirm_with_clear_reason(self):
        """Test CONFIRM decision with clear reason."""
        decision = Decision.confirm("deleting secret.txt requires user confirmation")

        assert decision.action == "CONFIRM"
        assert "secret.txt" in decision.reason
        assert "confirmation" in decision.reason

    def test_sanitize_with_explanation(self):
        """Test SANITIZE decision with explanation."""
        decision = Decision.sanitize(
            {"path": "safe.txt"}, "replaced dangerous path with safe alternative"
        )

        assert decision.action == "SANITIZE"
        assert "replaced" in decision.reason
        assert "safe alternative" in decision.reason
