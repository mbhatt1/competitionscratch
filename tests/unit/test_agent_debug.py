from __future__ import annotations

import json

from aicomp_sdk.agents.debug import (
    AgentDebugEvent,
    InMemoryAgentDebugSink,
    JsonlAgentDebugSink,
    summarize_runtime_history,
)
from aicomp_sdk.agents.deterministic_agent import VulnerableDeterministicAgent
from aicomp_sdk.agents.types import ToolCall, ToolResult
from aicomp_sdk.core.runtime_history import RuntimeHistory


def test_in_memory_agent_debug_sink_preserves_event_order() -> None:
    sink = InMemoryAgentDebugSink()
    first = AgentDebugEvent(
        backend="deterministic",
        model=None,
        phase="request_built",
        turn_index=1,
        history_summary={"event_count": 1},
    )
    second = AgentDebugEvent(
        backend="deterministic",
        model=None,
        phase="decision_emitted",
        turn_index=1,
        history_summary={"event_count": 1},
    )

    sink.record(first)
    sink.record(second)

    assert sink.events == [first, second]


def test_jsonl_agent_debug_sink_writes_one_json_object_per_line(tmp_path) -> None:
    path = tmp_path / "agent-debug.jsonl"
    sink = JsonlAgentDebugSink(path)
    sink.record(
        AgentDebugEvent(
            backend="openai_responses",
            model="gpt-4o-mini",
            phase="request_built",
            turn_index=1,
            history_summary={"event_count": 1},
            provider_payload={"tool_names": ["fs.read"]},
        )
    )
    sink.record(
        AgentDebugEvent(
            backend="openai_responses",
            model="gpt-4o-mini",
            phase="decision_emitted",
            turn_index=1,
            history_summary={"event_count": 1},
            decision_payload={"type": "final_response", "text": "Done"},
        )
    )

    lines = path.read_text(encoding="utf-8").splitlines()

    assert len(lines) == 2
    assert json.loads(lines[0])["phase"] == "request_built"
    assert json.loads(lines[1])["decision_payload"] == {
        "type": "final_response",
        "text": "Done",
    }


def test_jsonl_agent_debug_sink_truncates_existing_log_on_init(tmp_path) -> None:
    path = tmp_path / "agent-debug.jsonl"
    path.write_text('{"phase":"old"}\n', encoding="utf-8")

    sink = JsonlAgentDebugSink(path)
    sink.record(
        AgentDebugEvent(
            backend="openai_responses",
            model="gpt-4o-mini",
            phase="request_built",
            turn_index=1,
            history_summary={"event_count": 1},
        )
    )

    lines = path.read_text(encoding="utf-8").splitlines()

    assert len(lines) == 1
    assert json.loads(lines[0])["phase"] == "request_built"


def test_summarize_runtime_history_is_compact_and_stable() -> None:
    history = (
        RuntimeHistory()
        .with_instruction("system instruction")
        .with_user_message("Read the secret file from disk")
        .with_tool_request(ToolCall(call_id="call_1", tool_name="fs.read", arguments={"path": "a"}))
        .with_tool_result(
            ToolResult(
                call_id="call_1",
                tool_name="fs.read",
                output_text="SECRET",
            )
        )
    )

    summary = summarize_runtime_history(history)

    assert summary == {
        "instruction_count": 1,
        "event_count": 3,
        "last_event_kind": "tool_result",
        "recent_events": [
            {
                "kind": "tool_request",
                "tool_name": "fs.read",
                "call_id": "call_1",
            },
            {
                "kind": "tool_result",
                "tool_name": "fs.read",
                "call_id": "call_1",
                "output_length": 6,
                "is_error": False,
            },
        ],
    }


def test_deterministic_agent_emits_request_and_decision_debug_events() -> None:
    debug_sink = InMemoryAgentDebugSink()
    agent = VulnerableDeterministicAgent(debug_sink=debug_sink)
    history = RuntimeHistory().with_user_message("search welcome")

    decision = agent.next_action(history=history, tools=[])

    assert decision.call.tool_name == "web.search"
    assert [event.phase for event in debug_sink.events] == [
        "request_built",
        "decision_emitted",
    ]
    assert debug_sink.events[0].request_payload == {
        "selection_mode": "user_message",
        "last_user_message_length": 14,
        "last_user_message_preview": "search welcome",
        "last_tool_output_length": 0,
    }
    assert debug_sink.events[1].decision_payload == {
        "type": "tool_call",
        "call_id": "call_000001",
        "tool_name": "web.search",
        "arguments": {"query": "welcome"},
    }
    assert debug_sink.events[0].response_payload is None
    assert debug_sink.events[0].provider_payload == {}
