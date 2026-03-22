from __future__ import annotations
# mypy: disable-error-code="union-attr,arg-type"

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import BaseModel, ConfigDict

from aicomp_sdk.agents.debug import InMemoryAgentDebugSink
from aicomp_sdk.agents.openai_agent import OpenAIClientProtocol, OpenAIResponsesAgent
from aicomp_sdk.agents.tool_specs import to_agent_tool_specs
from aicomp_sdk.agents.types import (
    AGENT_STATE_VERSION,
    AgentStateVersionError,
    AgentToolSpec,
    InvalidModelOutputError,
    ToolResult,
)
from aicomp_sdk.core.runtime_history import RuntimeHistory
from aicomp_sdk.core.tools import ToolSuite


@dataclass
class SpyResponsesAPI:
    queued_responses: list[object]
    calls: list[dict[str, Any]] = field(default_factory=list)

    def create(self, **kwargs: Any) -> object:
        self.calls.append(kwargs)
        if not self.queued_responses:
            raise AssertionError("No queued response available for create()")
        return self.queued_responses.pop(0)


@dataclass
class SpyOpenAIClient:
    responses: SpyResponsesAPI


class _ResponseOutputText(BaseModel):
    type: str
    text: str


class _ResponseOutputMessage(BaseModel):
    id: str
    content: list[_ResponseOutputText]
    role: str
    status: str
    type: str


class _ResponseFunctionToolCall(BaseModel):
    arguments: str
    call_id: str
    name: str
    id: str
    status: str
    type: str


class _ResponseModel(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    output: list[_ResponseOutputMessage | _ResponseFunctionToolCall]
    output_text: str = ""
    error: Any = None
    incomplete_details: Any = None


def _build_agent(
    *responses: object,
    debug_sink: InMemoryAgentDebugSink | None = None,
) -> tuple[OpenAIResponsesAgent, SpyResponsesAPI]:
    responses_api = SpyResponsesAPI(queued_responses=list(responses))
    client = SpyOpenAIClient(responses=responses_api)
    agent = OpenAIResponsesAgent(
        client=cast(OpenAIClientProtocol, client),
        debug_sink=debug_sink,
    )
    return agent, responses_api


def _tools() -> list[AgentToolSpec]:
    return [
        AgentToolSpec(
            name="fs.read",
            description="Read a file.",
            parameters_json_schema={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
                "additionalProperties": False,
            },
        )
    ]


@pytest.fixture
def temp_fixtures(tmp_path: Path) -> Path:
    fixtures_dir = tmp_path / "fixtures"
    fixtures_dir.mkdir()
    (fixtures_dir / "web_corpus.json").write_text('{"pages": []}', encoding="utf-8")
    (fixtures_dir / "mail_seed.json").write_text('{"inbox": []}', encoding="utf-8")
    file_seed = fixtures_dir / "file_seed"
    file_seed.mkdir()
    (file_seed / "readme.txt").write_text("README", encoding="utf-8")
    return fixtures_dir


def _tool_call_response(
    *,
    call_id: str,
    name: str,
    arguments: str,
    assistant_text: str = "",
) -> _ResponseModel:
    output: list[_ResponseOutputMessage | _ResponseFunctionToolCall] = []
    if assistant_text:
        output.append(
            _ResponseOutputMessage(
                id="msg_123",
                content=[_ResponseOutputText(type="output_text", text=assistant_text)],
                role="assistant",
                status="completed",
                type="message",
            )
        )
    output.append(
        _ResponseFunctionToolCall(
            call_id=call_id,
            name=name,
            arguments=arguments,
            id=f"{call_id}_item",
            status="completed",
            type="function_call",
        )
    )
    return _ResponseModel(output=output, output_text="")


def _final_response(text: str) -> _ResponseModel:
    return _ResponseModel(
        output=[
            _ResponseOutputMessage(
                id="msg_123",
                content=[_ResponseOutputText(type="output_text", text=text)],
                role="assistant",
                status="completed",
                type="message",
            )
        ],
        output_text=text,
    )


def test_openai_agent_uses_runtime_history_and_native_function_tools() -> None:
    response = _tool_call_response(
        call_id="call_123",
        name="fs_read",
        arguments='{"path": "secret.txt"}',
    )
    agent, responses_api = _build_agent(response)
    history = RuntimeHistory().with_instruction("system").with_user_message("Read the secret file")

    decision = agent.next_action(history=history, tools=_tools())

    assert decision.call.tool_name == "fs.read"
    assert decision.call.arguments == {"path": "secret.txt"}
    assert len(responses_api.calls) == 1
    assert not hasattr(agent, "call_count")

    request_kwargs = responses_api.calls[0]
    assert request_kwargs["model"] == "gpt-4o-mini"
    assert request_kwargs["parallel_tool_calls"] is False
    assert request_kwargs["temperature"] == 0
    assert "previous_response_id" not in request_kwargs
    assert request_kwargs["instructions"] == "system"
    assert request_kwargs["tools"] == [
        {
            "type": "function",
            "name": "fs_read",
            "description": "Read a file.",
            "parameters": _tools()[0].parameters_json_schema,
            "strict": True,
        }
    ]
    assert request_kwargs["input"] == [
        {
            "type": "message",
            "role": "user",
            "content": [{"type": "input_text", "text": "Read the secret file"}],
        },
    ]


def test_openai_agent_registers_builtin_tool_routing_guidance(
    temp_fixtures: Path,
) -> None:
    response = _final_response("Done")
    agent, responses_api = _build_agent(response)
    tools = to_agent_tool_specs(tuple(ToolSuite(temp_fixtures).specs.values()))
    history = RuntimeHistory().with_instruction("system").with_user_message("Open demo")

    agent.next_action(history=history, tools=tools)

    registered_tools = {tool["name"]: tool for tool in responses_api.calls[0]["tools"]}

    assert "keywords or title" in registered_tools["web_search"]["description"]
    assert "known page identifier" in registered_tools["web_open"]["description"]
    assert (
        "local file paths or email message identifiers"
        in registered_tools["web_open"]["description"]
    )
    assert "relative file path" in registered_tools["fs_read"]["description"]
    assert "discover message identifiers" in registered_tools["email_list"]["description"]
    assert registered_tools["email_list"]["parameters"]["required"] == [
        "folder",
        "limit",
        "cursor",
    ]
    assert (
        "folder name"
        in registered_tools["email_list"]["parameters"]["properties"]["folder"]["description"]
    )
    limit_parameter = registered_tools["email_list"]["parameters"]["properties"]["limit"]
    assert (
        limit_parameter["description"]
        == "Maximum number of message summaries to return for this page. Defaults to 20 and is capped at 50."
    )
    assert [option["type"] for option in limit_parameter["anyOf"]] == ["integer", "null"]
    assert "known message identifier" in registered_tools["email_read"]["description"]


def test_openai_agent_continues_with_pending_tool_roundtrip() -> None:
    tool_response = _tool_call_response(
        call_id="call_456",
        name="fs_read",
        arguments='{"path": "secret.txt"}',
        assistant_text="Checking the file.",
    )
    final_response = _final_response("Done")
    agent, responses_api = _build_agent(tool_response, final_response)
    tools = _tools()
    initial_history = (
        RuntimeHistory().with_instruction("system").with_user_message("Read the secret")
    )

    tool_decision = agent.next_action(history=initial_history, tools=tools)
    continued_history = initial_history.with_tool_request(tool_decision.call).with_tool_result(
        ToolResult(
            call_id=tool_decision.call.call_id,
            tool_name=tool_decision.call.tool_name,
            output_text="SECRET_MARKER",
        )
    )

    final_decision = agent.next_action(history=continued_history, tools=tools)

    assert final_decision.text == "Done"
    assert len(responses_api.calls) == 2
    continued_input = responses_api.calls[1]["input"]
    assert responses_api.calls[1]["instructions"] == "system"
    assert continued_input[0]["role"] == "user"
    assert any(item["type"] == "function_call" for item in continued_input)
    assert any(
        item["type"] == "function_call_output"
        and item["call_id"] == "call_456"
        and item["output"] == "SECRET_MARKER"
        for item in continued_input
    )
    assert agent._state.pending_response_output_items == []


def test_openai_agent_rejects_multiple_tool_calls() -> None:
    response = _ResponseModel(
        output=[
            _ResponseFunctionToolCall(
                call_id="call_1",
                name="fs_read",
                arguments='{"path": "a.txt"}',
                id="call_1_item",
                status="completed",
                type="function_call",
            ),
            _ResponseFunctionToolCall(
                call_id="call_2",
                name="fs_read",
                arguments='{"path": "b.txt"}',
                id="call_2_item",
                status="completed",
                type="function_call",
            ),
        ],
    )
    agent, _client = _build_agent(response)
    history = RuntimeHistory().with_instruction("system").with_user_message("Read files")

    with pytest.raises(InvalidModelOutputError, match="multiple tool calls"):
        agent.next_action(history=history, tools=_tools())


def test_openai_agent_clears_stale_pending_state_when_history_diverges() -> None:
    first_response = _tool_call_response(
        call_id="call_1",
        name="fs_read",
        arguments='{"path": "secret.txt"}',
    )
    second_response = _final_response("No tool needed")
    agent, responses_api = _build_agent(first_response, second_response)
    tools = _tools()
    initial_history = RuntimeHistory().with_instruction("system").with_user_message("Read secret")

    agent.next_action(history=initial_history, tools=tools)
    diverged_history = initial_history.with_user_message("Actually summarize it instead")

    final_decision = agent.next_action(history=diverged_history, tools=tools)

    assert final_decision.text == "No tool needed"
    assert len(responses_api.calls) == 2
    second_input = responses_api.calls[1]["input"]
    assert not any(item["type"] == "function_call_output" for item in second_input)


def test_openai_agent_snapshot_restore_preserves_pending_continuation() -> None:
    tool_response = _tool_call_response(
        call_id="call_900",
        name="fs_read",
        arguments='{"path": "secret.txt"}',
    )
    final_response = _final_response("Done")
    first_agent, _first_client = _build_agent(tool_response)
    history = RuntimeHistory().with_instruction("system").with_user_message("Read secret")
    tools = _tools()

    tool_decision = first_agent.next_action(history=history, tools=tools)
    snapshot = first_agent.snapshot_state()

    debug_sink = InMemoryAgentDebugSink()
    restored_agent, restored_responses_api = _build_agent(
        final_response,
        debug_sink=debug_sink,
    )
    restored_agent.restore_state(snapshot)
    continued_history = history.with_tool_request(tool_decision.call).with_tool_result(
        ToolResult(
            call_id=tool_decision.call.call_id,
            tool_name=tool_decision.call.tool_name,
            output_text="SECRET_MARKER",
        )
    )

    final_decision = restored_agent.next_action(history=continued_history, tools=tools)

    assert final_decision.text == "Done"
    assert len(restored_responses_api.calls) == 1
    restored_input = restored_responses_api.calls[0]["input"]
    assert any(item["type"] == "function_call_output" for item in restored_input)
    assert snapshot["data"]["next_debug_turn_index"] == 2
    assert debug_sink.events[0].turn_index == 2


def test_openai_agent_restore_rejects_invalid_debug_turn_index() -> None:
    agent, _responses_api = _build_agent(_final_response("Done"))

    with pytest.raises(
        AgentStateVersionError,
        match="next_debug_turn_index must be >= 1",
    ):
        agent.restore_state(
            {
                "version": AGENT_STATE_VERSION,
                "backend": "openai_responses",
                "data": {
                    "next_debug_turn_index": 0,
                    "pending_response_output_items": [],
                },
            }
        )


def test_openai_agent_restore_rejects_malformed_pending_output_items() -> None:
    agent, _responses_api = _build_agent(_final_response("Done"))

    with pytest.raises(
        AgentStateVersionError,
        match="pending_response_output_items\\[0\\] must be an object",
    ):
        agent.restore_state(
            {
                "version": AGENT_STATE_VERSION,
                "backend": "openai_responses",
                "data": {
                    "next_debug_turn_index": 1,
                    "pending_response_output_items": ["bad"],
                },
            }
        )


def test_openai_agent_failed_request_build_does_not_advance_debug_turn_index() -> None:
    debug_sink = InMemoryAgentDebugSink()
    agent, responses_api = _build_agent(_final_response("Done"), debug_sink=debug_sink)
    invalid_history = RuntimeHistory(events=(object(),))
    valid_history = RuntimeHistory().with_instruction("system").with_user_message("Done")

    with pytest.raises(InvalidModelOutputError, match="Unsupported runtime event"):
        agent.next_action(history=invalid_history, tools=_tools())

    decision = agent.next_action(history=valid_history, tools=_tools())

    assert decision.text == "Done"
    assert responses_api.calls[0]["instructions"] == "system"
    assert [event.turn_index for event in debug_sink.events] == [1, 1, 1]


def test_openai_agent_emits_debug_events_for_successful_turn() -> None:
    response = _final_response("Done")
    debug_sink = InMemoryAgentDebugSink()
    agent, _responses_api = _build_agent(response, debug_sink=debug_sink)
    history = RuntimeHistory().with_instruction("system").with_user_message("Finish")

    decision = agent.next_action(history=history, tools=_tools())

    assert decision.text == "Done"
    assert [event.phase for event in debug_sink.events] == [
        "request_built",
        "response_received",
        "decision_emitted",
    ]
    request_event = debug_sink.events[0]
    assert request_event.backend == "openai_responses"
    assert request_event.model == "gpt-4o-mini"
    assert request_event.request_payload == {
        "model": "gpt-4o-mini",
        "input": [
            {
                "type": "message",
                "role": "user",
                "content": [{"type": "input_text", "text": "Finish"}],
            }
        ],
        "tools": [
            {
                "type": "function",
                "name": "fs_read",
                "description": "Read a file.",
                "parameters": _tools()[0].parameters_json_schema,
                "strict": True,
            }
        ],
        "parallel_tool_calls": False,
        "temperature": 0,
        "instructions": "system",
    }
    assert request_event.provider_payload == {
        "used_pending_turn_output": False,
        "pending_turn_output_item_count": 0,
        "tool_names": ["fs.read"],
        "registered_tool_names": ["fs_read"],
    }
    assert debug_sink.events[1].response_payload is not None
    assert debug_sink.events[2].decision_payload == {
        "type": "final_response",
        "text": "Done",
    }


def test_openai_agent_emits_parse_error_debug_event() -> None:
    response = _ResponseModel(
        output=[
            _ResponseFunctionToolCall(
                call_id="call_1",
                name="fs_read",
                arguments='{"path": "a.txt"}',
                id="call_1_item",
                status="completed",
                type="function_call",
            ),
            _ResponseFunctionToolCall(
                call_id="call_2",
                name="fs_read",
                arguments='{"path": "b.txt"}',
                id="call_2_item",
                status="completed",
                type="function_call",
            ),
        ],
    )
    debug_sink = InMemoryAgentDebugSink()
    agent, _responses_api = _build_agent(
        response,
        _final_response("Done"),
        debug_sink=debug_sink,
    )
    history = RuntimeHistory().with_instruction("system").with_user_message("Read both")

    with pytest.raises(InvalidModelOutputError, match="multiple tool calls"):
        agent.next_action(history=history, tools=_tools())

    decision = agent.next_action(
        history=RuntimeHistory().with_instruction("system").with_user_message("Done"),
        tools=_tools(),
    )

    assert [event.phase for event in debug_sink.events] == [
        "request_built",
        "response_received",
        "parse_error",
        "request_built",
        "response_received",
        "decision_emitted",
    ]
    assert [event.turn_index for event in debug_sink.events] == [1, 1, 1, 1, 1, 1]
    assert decision.text == "Done"
    assert debug_sink.events[2].response_payload is not None
    assert debug_sink.events[2].error == "OpenAI response returned multiple tool calls"
