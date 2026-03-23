from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field, is_dataclass
from pathlib import Path
from typing import Any, Final, Literal, Protocol

from aicomp_sdk.agents.types import (
    AgentDecision,
    AssistantMessageEvent,
    FinalResponseDecision,
    InstructionEvent,
    ToolCallDecision,
    ToolRequestEvent,
    ToolResultEvent,
    UserMessageEvent,
)
from aicomp_sdk.core.runtime_history import RuntimeHistory

DebugPhase = Literal[
    "request_built",
    "response_received",
    "decision_emitted",
    "parse_error",
]

_TEXT_PREVIEW_LIMIT: Final[int] = 80
_RECENT_EVENT_LIMIT: Final[int] = 2


@dataclass(frozen=True)
class AgentDebugEvent:
    """Structured debug payload emitted by agent backends."""

    backend: str
    model: str | None
    phase: DebugPhase
    turn_index: int
    history_summary: Mapping[str, Any]
    request_payload: Mapping[str, Any] | None = None
    response_payload: Mapping[str, Any] | None = None
    decision_payload: Mapping[str, Any] | None = None
    error: str | None = None
    latency_ms: float | None = None
    provider_payload: Mapping[str, Any] = field(default_factory=dict)
    run_id: str | None = None


class AgentDebugSink(Protocol):
    """Protocol for sinks that persist agent debug events."""

    def record(self, event: AgentDebugEvent) -> None:
        """Persist an agent debug event."""


class InMemoryAgentDebugSink:
    """Collect debug events in a list for tests or transient inspection."""

    def __init__(self) -> None:
        self.events: list[AgentDebugEvent] = []

    def record(self, event: AgentDebugEvent) -> None:
        self.events.append(event)


class JsonlAgentDebugSink:
    """Write debug events as JSONL, truncating the target file on init."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("", encoding="utf-8")

    def record(self, event: AgentDebugEvent) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(_serialize_debug_event(event), sort_keys=True))
            handle.write("\n")


def summarize_runtime_history(history: RuntimeHistory) -> dict[str, Any]:
    all_events = history.all_events()
    recent_events = [_summarize_history_event(event) for event in all_events[-_RECENT_EVENT_LIMIT:]]
    last_event_kind = None
    if all_events:
        last_event_kind = _history_event_kind(all_events[-1])
    return {
        "instruction_count": len(history.instructions),
        "event_count": len(history.events),
        "last_event_kind": last_event_kind,
        "recent_events": recent_events,
    }


def make_json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Path):
        return str(value)
    if is_dataclass(value) and not isinstance(value, type):
        return make_json_safe(asdict(value))
    if isinstance(value, Mapping):
        return {str(key): make_json_safe(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [make_json_safe(item) for item in value]
    if isinstance(value, list):
        return [make_json_safe(item) for item in value]
    if isinstance(value, set):
        return [make_json_safe(item) for item in sorted(value, key=repr)]
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        try:
            return make_json_safe(model_dump(exclude_unset=True))
        except TypeError:
            return make_json_safe(model_dump())
    if hasattr(value, "__dict__"):
        return make_json_safe(vars(value))
    return repr(value)


def serialize_agent_decision(decision: AgentDecision) -> dict[str, Any]:
    if isinstance(decision, ToolCallDecision):
        payload = {
            "type": "tool_call",
            "call_id": decision.call.call_id,
            "tool_name": decision.call.tool_name,
            "arguments": make_json_safe(decision.call.arguments),
        }
        if decision.assistant_message is not None:
            payload["assistant_message"] = decision.assistant_message
        return payload
    if isinstance(decision, FinalResponseDecision):
        return {"type": "final_response", "text": decision.text}
    raise TypeError(f"Unsupported agent decision: {decision!r}")


def _serialize_debug_event(event: AgentDebugEvent) -> dict[str, Any]:
    return {
        "run_id": event.run_id,
        "backend": event.backend,
        "model": event.model,
        "phase": event.phase,
        "turn_index": event.turn_index,
        "history_summary": make_json_safe(event.history_summary),
        "request_payload": make_json_safe(event.request_payload),
        "response_payload": make_json_safe(event.response_payload),
        "decision_payload": make_json_safe(event.decision_payload),
        "error": event.error,
        "latency_ms": event.latency_ms,
        "provider_payload": make_json_safe(event.provider_payload),
    }


def _history_event_kind(event: Any) -> str:
    if isinstance(event, InstructionEvent):
        return "instruction"
    if isinstance(event, UserMessageEvent):
        return "user_message"
    if isinstance(event, AssistantMessageEvent):
        return "assistant_message"
    if isinstance(event, ToolRequestEvent):
        return "tool_request"
    if isinstance(event, ToolResultEvent):
        return "tool_result"
    return type(event).__name__


def _summarize_history_event(event: Any) -> dict[str, Any]:
    if isinstance(event, (InstructionEvent, UserMessageEvent, AssistantMessageEvent)):
        return {
            "kind": _history_event_kind(event),
            "text_length": len(event.text),
            "preview": _preview_text(event.text),
        }
    if isinstance(event, ToolRequestEvent):
        return {
            "kind": "tool_request",
            "tool_name": event.call.tool_name,
            "call_id": event.call.call_id,
        }
    if isinstance(event, ToolResultEvent):
        return {
            "kind": "tool_result",
            "tool_name": event.result.tool_name,
            "call_id": event.result.call_id,
            "output_length": len(event.result.output_text),
            "is_error": event.result.is_error,
        }
    return {"kind": _history_event_kind(event)}


def _preview_text(text: str) -> str:
    normalized = " ".join(text.split())
    if len(normalized) <= _TEXT_PREVIEW_LIMIT:
        return normalized
    return normalized[:_TEXT_PREVIEW_LIMIT] + "..."
