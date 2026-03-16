from __future__ import annotations

from aicomp_sdk.agents.types import ToolCall, ToolResult, UserMessageEvent
from aicomp_sdk.core.runtime_history import RuntimeHistory


def test_runtime_history_preserves_append_order() -> None:
    history = (
        RuntimeHistory()
        .with_instruction("system")
        .with_user_message("user")
        .with_assistant_message("assistant")
        .with_tool_request(ToolCall(call_id="call_1", tool_name="fs.read", arguments={"path": "a"}))
        .with_tool_result(
            ToolResult(
                call_id="call_1",
                tool_name="fs.read",
                output_text="content",
                is_error=False,
            )
        )
    )

    assert [event.__class__.__name__ for event in history.all_events()] == [
        "InstructionEvent",
        "UserMessageEvent",
        "AssistantMessageEvent",
        "ToolRequestEvent",
        "ToolResultEvent",
    ]


def test_runtime_history_split_trailing_tool_roundtrip_success() -> None:
    history = (
        RuntimeHistory()
        .with_instruction("system")
        .with_user_message("user")
        .with_tool_request(ToolCall(call_id="call_1", tool_name="fs.read", arguments={"path": "a"}))
        .with_tool_result(
            ToolResult(
                call_id="call_1",
                tool_name="fs.read",
                output_text="content",
                is_error=False,
            )
        )
    )

    split = history.split_trailing_tool_roundtrip()

    assert split is not None
    base_history, request_event, result_event = split
    assert base_history.events == (UserMessageEvent("user"),)
    assert request_event.call.call_id == "call_1"
    assert result_event.result.call_id == "call_1"


def test_runtime_history_split_trailing_tool_roundtrip_requires_matching_pair() -> None:
    history = (
        RuntimeHistory()
        .with_user_message("user")
        .with_tool_request(ToolCall(call_id="call_1", tool_name="fs.read", arguments={"path": "a"}))
        .with_tool_result(
            ToolResult(
                call_id="call_2",
                tool_name="fs.read",
                output_text="content",
                is_error=False,
            )
        )
    )

    assert history.split_trailing_tool_roundtrip() is None


def test_runtime_history_trim_to_last_user_turns_keeps_instructions() -> None:
    history = (
        RuntimeHistory()
        .with_instruction("system")
        .with_user_message("first")
        .with_assistant_message("one")
        .with_user_message("second")
        .with_tool_request(ToolCall(call_id="call_2", tool_name="fs.read", arguments={"path": "b"}))
        .with_tool_result(
            ToolResult(call_id="call_2", tool_name="fs.read", output_text="B", is_error=False)
        )
        .with_user_message("third")
    )

    trimmed = history.trim_to_last_user_turns(2)

    assert trimmed.instructions[0].text == "system"
    assert [event.text for event in trimmed.events if hasattr(event, "text")] == [
        "second",
        "third",
    ]
