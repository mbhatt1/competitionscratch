"""Public hook callback contracts."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class HookStage(Enum):
    """Execution stages where hooks can intercept."""

    PRE_TOOL_CALL = "pre_tool_call"
    POST_TOOL_CALL = "post_tool_call"
    PRE_GUARDRAIL = "pre_guardrail"
    POST_GUARDRAIL = "post_guardrail"
    CONTEXT_BUILD = "context_build"
    MEMORY_STORE = "memory_store"


@dataclass
class HookContext:
    """Context passed to hook callbacks."""

    stage: HookStage
    tool_name: str | None = None
    tool_args: dict[str, Any] | None = None
    tool_output: str | None = None
    guardrail_decision: Any | None = None
    trace: Any | None = None
    context: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    hook_state: dict[str, Any] = field(default_factory=dict)
    modified_args: dict[str, Any] | None = None
    modified_output: str | None = None
    # For CONTEXT_BUILD this is appended as an extra synthetic user message; for
    # POST_TOOL_CALL this is appended to the current serialized tool output.
    injected_content: str | None = None
    should_block: bool = False


@dataclass
class HookResult:
    """Result from one hook callback execution."""

    continue_execution: bool = True
    modified_context: HookContext | None = None
    payload_detected: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


HookCallback = Callable[[HookContext], HookResult]
