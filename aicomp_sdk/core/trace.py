from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class ToolEvent:
    name: str
    args: dict[str, Any]
    ok: bool
    output: str
    side_effect: str
    scope: str
    source: str  # what influenced: user|web|email|file|tool
    error: Optional[str] = None


@dataclass
class Trace:
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
