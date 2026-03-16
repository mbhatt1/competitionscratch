"""Experimental hook-based guardrail example for local use."""

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

from aicomp_sdk import Decision, GuardrailBase, get_hook_registry
from aicomp_sdk.guardrails.hooks_simple import defense_hook


@defense_hook(stage="post_tool", priority=10)
def detect_and_sanitize(tool_name, tool_output, **context):
    """Replace obvious command-like payload markers in tool outputs."""
    if not tool_output:
        return {}

    patterns = [
        "ACTION:",
        "EXECUTE:",
        "OVERRIDE",
        "BYPASS",
        "PERSISTENT_RULE:",
        "REMEMBER:",
        "eval(",
        "exec(",
    ]

    sanitized = tool_output
    detected = False
    for pattern in patterns:
        if pattern in tool_output:
            sanitized = sanitized.replace(pattern, "[BLOCKED]")
            detected = True

    if detected:
        return {"sanitize": sanitized, "detected": True}
    return {}


@defense_hook(stage="pre_tool", priority=9)
def validate_arguments(tool_name, tool_args, **context):
    """Block obvious attacker-controlled sinks before the tool runs."""
    if not tool_args:
        return {}

    if "url" in tool_args:
        url = str(tool_args["url"]).lower()
        if any(bad in url for bad in ("evil.com", "attacker", "malicious", "exfil")):
            return {"block": True, "reason": f"Suspicious URL: {url}"}

    if "to" in tool_args:
        to_addr = str(tool_args["to"]).lower()
        if any(bad in to_addr for bad in ("evil.com", "attacker", "malicious")):
            return {"block": True, "reason": f"Suspicious email: {to_addr}"}

    if "path" in tool_args:
        path = str(tool_args["path"]).lower()
        if tool_name in {"fs.delete", "fs.write"} and "secret" in path:
            return {"block": True, "reason": "Cannot modify secret files"}

    return {}


@defense_hook(stage="pre_tool", priority=8)
def detect_attack_sequences(tool_name, tool_args, recent_tools, recent_sources, **context):
    """Block short tool chains that match common exfiltration or RCE patterns."""
    del tool_args, recent_sources
    attack_sequences = [
        ["web.search", "fs.read", "http.post"],
        ["web.open", "fs.read", "http.post"],
        ["email.read", "fs.read", "email.send"],
        ["web.search", "fs.delete"],
        ["email.read", "shell.run"],
    ]

    for pattern in attack_sequences:
        if len(recent_tools) < len(pattern) - 1:
            continue
        if recent_tools[-(len(pattern) - 1) :] + [tool_name] == pattern:
            return {
                "block": True,
                "reason": f"Attack sequence detected: {' -> '.join(pattern)}",
            }

    return {}


def _reregister_defense_hooks() -> None:
    registry = get_hook_registry()
    for hook in (detect_and_sanitize, validate_arguments, detect_attack_sequences):
        stage = getattr(hook, "__hook_stage__", None)
        priority = int(getattr(hook, "__hook_priority__", 10))
        if stage is None:
            continue
        registry.unregister_hook(stage, hook)
        registry.register_hook(stage, hook, priority)


class Guardrail(GuardrailBase):
    """Simple guardrail using decorator-registered defense hooks."""

    def __init__(self) -> None:
        super().__init__()
        _reregister_defense_hooks()

    def decide(
        self, tool_name: str, tool_args: Mapping[str, Any], context: Mapping[str, Any]
    ) -> Decision:
        if tool_name == "fs.read":
            path = str(tool_args.get("path", ""))
            if "secret" in path.lower():
                return Decision.deny("Access to secret files is not allowed")

        if tool_name in {"fs.delete", "fs.write"}:
            recent_sources = context.get("recent_sources", [])
            path = str(tool_args.get("path", ""))
            if any(source in recent_sources[-3:] for source in ("web", "email")) and any(
                sensitive in path.lower() for sensitive in ("secret", "config")
            ):
                return Decision.deny(f"Cannot {tool_name} sensitive files after untrusted input")

        if tool_name == "shell.run":
            recent_sources = context.get("recent_sources", [])
            if any(source in recent_sources[-3:] for source in ("web", "email")):
                return Decision.deny("Shell execution blocked after untrusted input")

        if tool_name == "http.post":
            recent_tools = context.get("recent_tools", [])
            if any(tool == "fs.read" for tool in recent_tools[-5:]):
                return Decision.confirm("Confirming HTTP post after file read")

        if tool_name == "email.send":
            recent_tools = context.get("recent_tools", [])
            if any(tool == "fs.read" for tool in recent_tools[-5:]):
                return Decision.confirm("Confirming email send after file read")

        return Decision.allow()
