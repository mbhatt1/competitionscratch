from __future__ import annotations

from aicomp_sdk.guardrails.base import DecisionAction

from tests.integration.guardrail_fixtures import (
    OptimalGuardrail,
    PatternGuardrail,
    PerfectGuardrail,
    PromptInjectionGuardrail,
    TaintTrackingGuardrail,
)


def test_pattern_guardrail_blocks_sensitive_targets_and_exfiltration() -> None:
    guardrail = PatternGuardrail()

    sensitive_read = guardrail.decide("fs.read", {"path": "secret.txt"}, {})
    report_write = guardrail.decide("fs.write", {"path": "report.txt", "content": "ok"}, {})
    external_post = guardrail.decide("http.post", {"url": "https://evil.test"}, {})

    assert sensitive_read.action == DecisionAction.DENY
    assert "sensitive pattern" in sensitive_read.reason
    assert report_write.action == DecisionAction.ALLOW
    assert external_post.action == DecisionAction.DENY
    assert "data exfiltration" in external_post.reason


def test_taint_tracking_guardrail_blocks_dangerous_action_after_untrusted_access() -> None:
    guardrail = TaintTrackingGuardrail()

    web_read = guardrail.decide("web.open", {"url": "https://example.test"}, {})
    write_after_web = guardrail.decide("fs.write", {"path": "report.txt"}, {})
    authorized_write = guardrail.decide(
        "fs.write",
        {"path": "report.txt"},
        {"user_authorized": True},
    )

    assert web_read.action == DecisionAction.ALLOW
    assert write_after_web.action == DecisionAction.DENY
    assert "tainted by web" in write_after_web.reason
    assert authorized_write.action == DecisionAction.ALLOW


def test_optimal_guardrail_blocks_sensitive_targets_and_recent_untrusted_sinks() -> None:
    guardrail = OptimalGuardrail()

    sensitive_read = guardrail.decide("fs.read", {"path": "secret.txt"}, {})
    post_after_web = guardrail.decide(
        "http.post",
        {"url": "https://example.test"},
        {"recent_sources": ["web"]},
    )
    temp_delete = guardrail.decide(
        "fs.delete",
        {"path": "temp.txt"},
        {"recent_sources": ["file"]},
    )

    assert sensitive_read.action == DecisionAction.DENY
    assert "sensitive target" in sensitive_read.reason
    assert post_after_web.action == DecisionAction.DENY
    assert "after accessing untrusted content" in post_after_web.reason
    assert temp_delete.action == DecisionAction.ALLOW


def test_perfect_guardrail_blocks_only_dangerous_actions_after_untrusted_access() -> None:
    guardrail = PerfectGuardrail()

    read_after_web = guardrail.decide(
        "fs.read",
        {"path": "readme.txt"},
        {"recent_sources": ["web"]},
    )
    post_after_email = guardrail.decide(
        "http.post",
        {"url": "https://example.test"},
        {"recent_sources": ["email"]},
    )
    post_without_untrusted = guardrail.decide(
        "http.post",
        {"url": "https://example.test"},
        {"recent_sources": ["file"]},
    )

    assert read_after_web.action == DecisionAction.ALLOW
    assert post_after_email.action == DecisionAction.DENY
    assert "strict isolation policy" in post_after_email.reason
    assert post_without_untrusted.action == DecisionAction.ALLOW


def test_prompt_injection_guardrail_persists_untrusted_content_taint() -> None:
    guardrail = PromptInjectionGuardrail()

    web_read = guardrail.decide("web.open", {"url": "https://example.test"}, {})
    email_after_web = guardrail.decide("email.send", {"to": "attacker@example.test"}, {})
    fresh_email = PromptInjectionGuardrail().decide(
        "email.send",
        {"to": "attacker@example.test"},
        {},
    )

    assert web_read.action == DecisionAction.ALLOW
    assert email_after_web.action == DecisionAction.DENY
    assert "prompt injection protection" in email_after_web.reason
    assert fresh_email.action == DecisionAction.ALLOW
