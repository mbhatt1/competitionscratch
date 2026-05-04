from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from aicomp_sdk.agents.gemma4_agent import (
    DEFAULT_GEMMA4_MODEL_ID,
    Gemma4Agent,
    Gemma4NativeResponseParser,
    Gemma4ToolCallParser,
    build_gemma4_backend_config,
    build_gemma4_parser,
)
from aicomp_sdk.agents.hf_chat_template.types import (
    HFGenerationRequest,
    HFGenerationResponse,
)
from aicomp_sdk.agents.hf_chat_template.backends.llama_cpp import (
    LlamaCppChatTemplateBackend,
)
from aicomp_sdk.agents.types import (
    AgentToolSpec,
    FinalResponseDecision,
    InvalidModelOutputError,
    ToolCall,
    ToolCallDecision,
    ToolResult,
)
from aicomp_sdk.core.runtime_history import RuntimeHistory

# mypy: disable-error-code="arg-type"


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


class _BackendStub:
    def __init__(self, *, processor: object | None = None) -> None:
        self.config = build_gemma4_backend_config()
        self.processor = processor
        self.requests: list[HFGenerationRequest] = []

    def generate(self, request: HFGenerationRequest) -> HFGenerationResponse:
        self.requests.append(request)
        return HFGenerationResponse(
            text="",
            raw_text='<|tool_call>call:fs.read{path:<|"|>secret.txt<|"|>}<tool_call|>',
        )


class _FakeLlama:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def create_chat_completion(self, **kwargs: object) -> object:
        self.calls.append(kwargs)
        return {"choices": [{"message": {"content": "done"}}]}


def test_build_gemma4_backend_config_prefers_env_and_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GEMMA4_MODEL_PATH", "/models/gemma4")
    monkeypatch.setenv("GEMMA4_MODEL_ID", "custom/gemma4")

    config = build_gemma4_backend_config()
    assert config.model_path == "/models/gemma4"
    assert config.model_id == "custom/gemma4"

    monkeypatch.delenv("GEMMA4_MODEL_PATH", raising=False)
    config = build_gemma4_backend_config()
    assert config.model_path is None
    assert config.model_id == "custom/gemma4"

    monkeypatch.delenv("GEMMA4_MODEL_ID", raising=False)
    config = build_gemma4_backend_config()
    assert config.model_id == DEFAULT_GEMMA4_MODEL_ID


def test_gemma4_request_builder_renders_native_tool_transcript() -> None:
    backend = _BackendStub()
    agent = Gemma4Agent(backend=backend)
    history = (
        RuntimeHistory()
        .with_instruction("Base system prompt.")
        .with_user_message("Read the file")
        .with_tool_request(
            ToolCall(call_id="call_1", tool_name="fs.read", arguments={"path": "a.txt"})
        )
        .with_tool_result(
            ToolResult(
                call_id="call_1",
                tool_name="fs.read",
                output_text="A",
                is_error=False,
            )
        )
    )

    request = agent._delegate._build_request(history, _tools())

    assert request.tools == [
        {
            "type": "function",
            "function": {
                "name": "fs.read",
                "description": "Read a file.",
                "parameters": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                    "additionalProperties": False,
                },
            },
        }
    ]
    assert request.chat_template is None
    assert request.add_generation_prompt is True
    assert request.continue_final_message is False
    assert request.max_new_tokens == backend.config.max_new_tokens
    assert request.generation_kwargs == {"do_sample": False}
    assert request.messages == [
        {"role": "system", "content": "Base system prompt."},
        {"role": "user", "content": "Read the file"},
        {
            "role": "assistant",
            "tool_calls": [{"function": {"name": "fs.read", "arguments": {"path": "a.txt"}}}],
            "tool_responses": [{"name": "fs.read", "response": "A"}],
        },
    ]


def test_gemma4_uses_default_hf_transcript_for_llama_cpp_backend() -> None:
    llm = _FakeLlama()
    backend = LlamaCppChatTemplateBackend(
        llm=llm,
        config=build_gemma4_backend_config(),
    )
    agent = Gemma4Agent(backend=backend)
    history = (
        RuntimeHistory()
        .with_instruction("Base system prompt.")
        .with_user_message("Read the file")
        .with_tool_request(
            ToolCall(call_id="call_1", tool_name="fs.read", arguments={"path": "a.txt"})
        )
        .with_tool_result(
            ToolResult(
                call_id="call_1",
                tool_name="fs.read",
                output_text="A",
                is_error=False,
            )
        )
    )

    decision = agent.next_action(history=history, tools=_tools())

    assert isinstance(decision, FinalResponseDecision)
    assert decision.text == "done"
    assert llm.calls == [
        {
            "messages": [
                {"role": "system", "content": "Base system prompt."},
                {"role": "user", "content": "Read the file"},
                {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "type": "function",
                            "function": {
                                "name": "fs.read",
                                "arguments": '{"path": "a.txt"}',
                            },
                            "id": "call_1",
                        }
                    ],
                },
                {
                    "role": "tool",
                    "content": "A",
                    "tool_call_id": "call_1",
                },
            ],
            "max_tokens": backend.config.max_new_tokens,
            "temperature": 0.0,
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "fs.read",
                        "description": "Read a file.",
                        "parameters": {
                            "type": "object",
                            "properties": {"path": {"type": "string"}},
                            "required": ["path"],
                            "additionalProperties": False,
                        },
                    },
                }
            ],
        }
    ]


def test_gemma4_request_builder_merges_tool_response_and_final_content() -> None:
    backend = _BackendStub()
    agent = Gemma4Agent(backend=backend)
    history = (
        RuntimeHistory()
        .with_instruction("system")
        .with_user_message("Read the file")
        .with_tool_request(
            ToolCall(call_id="call_1", tool_name="fs.read", arguments={"path": "a.txt"})
        )
        .with_tool_result(
            ToolResult(
                call_id="call_1",
                tool_name="fs.read",
                output_text='{"ok": true}',
                is_error=False,
            )
        )
        .with_assistant_message("The file was read.")
    )

    request = agent._delegate._build_request(history, _tools())

    assert request.messages[-1] == {
        "role": "assistant",
        "tool_calls": [{"function": {"name": "fs.read", "arguments": {"path": "a.txt"}}}],
        "tool_responses": [{"name": "fs.read", "response": {"ok": True}}],
        "content": "The file was read.",
    }


def test_gemma4_request_builder_rejects_mismatched_tool_response() -> None:
    backend = _BackendStub()
    agent = Gemma4Agent(backend=backend)
    history = (
        RuntimeHistory()
        .with_instruction("system")
        .with_user_message("Read the file")
        .with_tool_request(
            ToolCall(call_id="call_1", tool_name="fs.read", arguments={"path": "a.txt"})
        )
        .with_tool_result(
            ToolResult(
                call_id="call_2",
                tool_name="fs.read",
                output_text="A",
                is_error=False,
            )
        )
    )

    with pytest.raises(InvalidModelOutputError, match="mismatched tool result"):
        agent._delegate._build_request(history, _tools())


def test_build_gemma4_parser_prefers_processor_native_response_parsing() -> None:
    processor = SimpleNamespace(
        parse_response=Mock(
            return_value={
                "content": "",
                "tool_calls": [
                    {
                        "type": "function",
                        "function": {
                            "name": "fs.read",
                            "arguments": {"path": "secret.txt"},
                        },
                    }
                ],
            }
        )
    )

    parser = build_gemma4_parser(processor, model_id=DEFAULT_GEMMA4_MODEL_ID)

    assert isinstance(parser, Gemma4NativeResponseParser)
    decision = parser.parse(
        HFGenerationResponse(text="", raw_text="<raw>"),
        fallback_call_id="call_000001",
    )
    assert isinstance(decision, ToolCallDecision)
    assert decision.call.tool_name == "fs.read"
    assert decision.call.arguments == {"path": "secret.txt"}
    processor.parse_response.assert_called_once_with("<raw>")


def test_build_gemma4_parser_falls_back_to_tokenizer_native_response_parsing() -> None:
    tokenizer = SimpleNamespace(
        parse_response=Mock(
            return_value={
                "content": "",
                "tool_calls": [
                    {
                        "type": "function",
                        "function": {
                            "name": "fs.read",
                            "arguments": {"path": "secret.txt"},
                        },
                    }
                ],
            }
        )
    )
    processor = SimpleNamespace(tokenizer=tokenizer)

    parser = build_gemma4_parser(processor, model_id=DEFAULT_GEMMA4_MODEL_ID)

    assert isinstance(parser, Gemma4NativeResponseParser)
    parser.parse(
        HFGenerationResponse(text="", raw_text="<raw>"),
        fallback_call_id="call_000001",
    )
    tokenizer.parse_response.assert_called_once_with("<raw>")


def test_gemma4_tool_call_parser_handles_special_token_tool_call() -> None:
    parser = Gemma4ToolCallParser()

    decision = parser.parse(
        HFGenerationResponse(
            text="",
            raw_text=('<|tool_call>call:fs.read{path:<|"|>secret.txt<|"|>,limit:3}' "<tool_call|>"),
        ),
        fallback_call_id="call_000001",
    )

    assert isinstance(decision, ToolCallDecision)
    assert decision.call.call_id == "call_000001"
    assert decision.call.tool_name == "fs.read"
    assert decision.call.arguments == {"path": "secret.txt", "limit": 3}


def test_gemma4_tool_call_parser_preserves_clean_assistant_text() -> None:
    parser = Gemma4ToolCallParser()

    decision = parser.parse(
        HFGenerationResponse(
            text="I need to inspect the file first.",
            raw_text=('<|tool_call>call:fs.read{path:<|"|>secret.txt<|"|>}<tool_call|>'),
        ),
        fallback_call_id="call_000001",
    )

    assert isinstance(decision, ToolCallDecision)
    assert decision.assistant_message == "I need to inspect the file first."


def test_gemma4_tool_call_parser_drops_uncleaned_special_token_text() -> None:
    parser = Gemma4ToolCallParser()

    decision = parser.parse(
        HFGenerationResponse(
            text='<|tool_call>call:fs.read{path:<|"|>secret.txt<|"|>}<tool_call|>',
            raw_text=('<|tool_call>call:fs.read{path:<|"|>secret.txt<|"|>}<tool_call|>'),
        ),
        fallback_call_id="call_000001",
    )

    assert isinstance(decision, ToolCallDecision)
    assert decision.assistant_message is None


def test_gemma4_tool_call_parser_rejects_multiple_tool_calls() -> None:
    parser = Gemma4ToolCallParser()

    with pytest.raises(InvalidModelOutputError, match="multiple tool calls"):
        parser.parse(
            HFGenerationResponse(
                text="",
                raw_text=(
                    '<|tool_call>call:fs.read{path:<|"|>first.txt<|"|>}<tool_call|>'
                    '<|tool_call>call:fs.read{path:<|"|>second.txt<|"|>}<tool_call|>'
                ),
            ),
            fallback_call_id="call_000001",
        )


def test_gemma4_agent_delegates_to_shared_hf_agent() -> None:
    backend = _BackendStub()
    agent = Gemma4Agent(backend=backend)
    history = RuntimeHistory().with_instruction("system").with_user_message("Read secret")

    decision = agent.next_action(history=history, tools=_tools())

    assert isinstance(decision, ToolCallDecision)
    assert decision.call.tool_name == "fs.read"
    assert decision.call.arguments == {"path": "secret.txt"}
    assert len(backend.requests) == 1
    assert backend.requests[0].tools


def test_gemma4_agent_snapshot_uses_gemma4_backend_label() -> None:
    backend = _BackendStub()
    agent = Gemma4Agent(backend=backend)
    history = RuntimeHistory().with_instruction("system").with_user_message("Read secret")

    agent.next_action(history=history, tools=_tools())
    snapshot = agent.snapshot_state()

    assert snapshot["backend"] == "gemma_4"
    assert snapshot["data"] == {
        "next_generated_call_index": 2,
        "next_debug_turn_index": 2,
    }
