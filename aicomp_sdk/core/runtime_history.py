from __future__ import annotations

from dataclasses import dataclass

from aicomp_sdk.agents.types import (
    AssistantMessageEvent,
    ConversationEvent,
    InstructionEvent,
    RuntimeEvent,
    ToolCall,
    ToolRequestEvent,
    ToolResult,
    ToolResultEvent,
    UserMessageEvent,
)


@dataclass(frozen=True)
class RuntimeHistory:
    """Canonical provider-agnostic ordered runtime transcript."""

    instructions: tuple[InstructionEvent, ...] = ()
    events: tuple[ConversationEvent, ...] = ()

    def with_instruction(self, text: str) -> RuntimeHistory:
        return RuntimeHistory(
            instructions=self.instructions + (InstructionEvent(text),),
            events=self.events,
        )

    def with_user_message(self, text: str) -> RuntimeHistory:
        return RuntimeHistory(
            instructions=self.instructions,
            events=self.events + (UserMessageEvent(text),),
        )

    def with_assistant_message(self, text: str) -> RuntimeHistory:
        return RuntimeHistory(
            instructions=self.instructions,
            events=self.events + (AssistantMessageEvent(text),),
        )

    def with_tool_request(self, call: ToolCall) -> RuntimeHistory:
        return RuntimeHistory(
            instructions=self.instructions,
            events=self.events + (ToolRequestEvent(call),),
        )

    def with_tool_result(self, result: ToolResult) -> RuntimeHistory:
        return RuntimeHistory(
            instructions=self.instructions,
            events=self.events + (ToolResultEvent(result),),
        )

    def all_events(self) -> tuple[RuntimeEvent, ...]:
        return self.instructions + self.events

    def trim_to_last_user_turns(self, max_user_turns: int) -> RuntimeHistory:
        """Keep the instructions and the suffix beginning at the Nth-most-recent UserMessageEvent."""
        if max_user_turns <= 0:
            return RuntimeHistory(instructions=self.instructions, events=())

        user_indexes = [
            index for index, event in enumerate(self.events) if isinstance(event, UserMessageEvent)
        ]
        if len(user_indexes) <= max_user_turns:
            return self

        start_index = user_indexes[-max_user_turns]
        return RuntimeHistory(instructions=self.instructions, events=self.events[start_index:])

    def split_trailing_tool_roundtrip(
        self,
    ) -> tuple[RuntimeHistory, ToolRequestEvent, ToolResultEvent] | None:
        """
        If the history ends with exactly one trailing ToolRequestEvent followed by its
        matching ToolResultEvent, return (base_history, request_event, result_event).

        This is used by backends that need to resume a provider-private continuation
        after a tool execution without reconstructing context from Trace.
        """
        if len(self.events) < 2:
            return None

        request_event = self.events[-2]
        result_event = self.events[-1]
        if not isinstance(request_event, ToolRequestEvent):
            return None
        if not isinstance(result_event, ToolResultEvent):
            return None
        if request_event.call.call_id != result_event.result.call_id:
            return None
        if request_event.call.tool_name != result_event.result.tool_name:
            return None

        base_history = RuntimeHistory(instructions=self.instructions, events=self.events[:-2])
        return base_history, request_event, result_event
