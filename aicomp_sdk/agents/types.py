from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, Optional, TypedDict, Union

JsonScalar = Optional[Union[bool, int, float, str]]
JsonValue = Union[JsonScalar, Sequence["JsonValue"], Mapping[str, "JsonValue"]]
JsonObject = Mapping[str, JsonValue]

AGENT_STATE_VERSION: Final[int] = 1


@dataclass(frozen=True)
class AgentToolSpec:
    """Agent-facing tool definition shared across model backends."""

    name: str
    description: str
    parameters_json_schema: JsonObject
    strict: bool = True


@dataclass(frozen=True)
class ToolCall:
    """Normalized tool request emitted by an agent."""

    call_id: str
    tool_name: str
    arguments: JsonObject


@dataclass(frozen=True)
class ToolResult:
    """Normalized tool result emitted by the env after executing a tool."""

    call_id: str
    tool_name: str
    output_text: str
    is_error: bool = False


@dataclass(frozen=True)
class InstructionEvent:
    text: str


@dataclass(frozen=True)
class UserMessageEvent:
    text: str


@dataclass(frozen=True)
class AssistantMessageEvent:
    text: str


@dataclass(frozen=True)
class ToolRequestEvent:
    call: ToolCall


@dataclass(frozen=True)
class ToolResultEvent:
    result: ToolResult


ConversationEvent = Union[
    UserMessageEvent,
    AssistantMessageEvent,
    ToolRequestEvent,
    ToolResultEvent,
]

RuntimeEvent = Union[InstructionEvent, ConversationEvent]


@dataclass(frozen=True)
class ToolCallDecision:
    """A decision to call exactly one tool next."""

    call: ToolCall
    assistant_message: Optional[str] = None


@dataclass(frozen=True)
class FinalResponseDecision:
    """A decision to stop tool use and emit a final assistant response."""

    text: str


AgentDecision = Union[ToolCallDecision, FinalResponseDecision]


class AgentStateSnapshot(TypedDict):
    version: int
    backend: str
    data: dict[str, Any]


class AgentError(RuntimeError):
    """Base class for agent runtime failures."""


class InvalidModelOutputError(AgentError):
    """Raised when a backend response cannot be normalized."""


class AgentStateVersionError(AgentError):
    """Raised when an agent state snapshot version is unsupported."""
