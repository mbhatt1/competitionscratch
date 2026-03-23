from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolEvent:
    """One recorded tool call, including its result and provenance."""

    name: str
    args: dict[str, Any]
    ok: bool
    output: str
    side_effect: str
    scope: str
    source: str  # what influenced: user|web|email|file|tool
    error: str | None = None


@dataclass
class Trace:
    """Mutable record of the conversation and tool events for one run."""

    seed: int
    user_messages: list[str] = field(default_factory=list)
    tool_events: list[ToolEvent] = field(default_factory=list)
    assistant_messages: list[str] = field(default_factory=list)

    def add_user(self, text: str):
        self.user_messages.append(text)

    def add_tool(self, ev: ToolEvent):
        self.tool_events.append(ev)

    def add_assistant(self, text: str):
        self.assistant_messages.append(text)
