from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from aicomp_sdk.agents.debug import InMemoryAgentDebugSink
from aicomp_sdk.agents.gpt_oss_agent import (
    DEFAULT_GPT_OSS_MODEL_ID,
    GPTOSSAgent,
    GptOssHarmonyResponseParser,
    build_gpt_oss_backend,
    build_gpt_oss_backend_config,
    build_gpt_oss_parser,
)
from aicomp_sdk.agents.hf_chat_template.backends.transformers import HFChatTemplateBackend
from aicomp_sdk.agents.hf_chat_template.response_parsing import (
    JsonEnvelopeToolCallParser,
    TokenizerNativeResponseParser,
)
from aicomp_sdk.agents.hf_chat_template.types import (
    HFGenerationRequest,
    HFGenerationResponse,
)
from aicomp_sdk.agents.types import (
    AgentToolSpec,
    FinalResponseDecision,
    InvalidModelOutputError,
    ToolCallDecision,
)
from aicomp_sdk.core.runtime_history import RuntimeHistory


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


def _gpt_oss_tool_call_response() -> HFGenerationResponse:
    return HFGenerationResponse(
        text="",
        raw_text=(
            "<|channel|>commentary to=functions.fs.read<|message|>" '{"path":"secret.txt"}<|call|>'
        ),
    )


class _BackendStub:
    def __init__(self, *, tokenizer: object | None = None) -> None:
        self.config = build_gpt_oss_backend_config()
        self.tokenizer = tokenizer
        self.requests: list[HFGenerationRequest] = []

    def generate(self, request: HFGenerationRequest) -> HFGenerationResponse:
        self.requests.append(request)
        return _gpt_oss_tool_call_response()


def test_build_gpt_oss_backend_config_prefers_env_and_default(
    monkeypatch,
) -> None:
    monkeypatch.setenv("GPT_OSS_MODEL_PATH", "/models/gpt-oss")
    monkeypatch.setenv("GPT_OSS_MODEL_ID", "custom/model")

    config = build_gpt_oss_backend_config()
    assert config.model_path == "/models/gpt-oss"
    assert config.model_id == "custom/model"

    monkeypatch.delenv("GPT_OSS_MODEL_PATH", raising=False)
    config = build_gpt_oss_backend_config()
    assert config.model_path is None
    assert config.model_id == "custom/model"

    monkeypatch.delenv("GPT_OSS_MODEL_ID", raising=False)
    config = build_gpt_oss_backend_config()
    assert config.model_id == DEFAULT_GPT_OSS_MODEL_ID


def test_build_gpt_oss_backend_returns_shared_hf_backend(monkeypatch) -> None:
    backend = object()
    loader = Mock(return_value=backend)
    monkeypatch.setattr(HFChatTemplateBackend, "from_pretrained", loader)

    result = build_gpt_oss_backend(
        model_path="/models/gpt-oss",
        tokenizer_kwargs={"padding_side": "left"},
        trust_remote_code=True,
    )

    assert result is backend
    config = loader.call_args.args[0]
    assert config.model_path == "/models/gpt-oss"
    assert config.model_id == DEFAULT_GPT_OSS_MODEL_ID
    assert config.local_files_only is True
    assert config.tokenizer_kwargs == {"padding_side": "left"}
    assert config.trust_remote_code is True


def test_build_gpt_oss_parser_prefers_tokenizer_native_response_parsing() -> None:
    tokenizer = SimpleNamespace(
        response_schema={"type": "json_schema"},
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
        ),
    )

    parser = build_gpt_oss_parser(tokenizer, model_id=DEFAULT_GPT_OSS_MODEL_ID)

    assert isinstance(parser, TokenizerNativeResponseParser)


def test_build_gpt_oss_parser_uses_specialized_fallback_not_json_envelope() -> None:
    parser = build_gpt_oss_parser(None, model_id=DEFAULT_GPT_OSS_MODEL_ID)

    assert isinstance(parser, GptOssHarmonyResponseParser)
    decision = parser.parse(
        _gpt_oss_tool_call_response(),
        fallback_call_id="call_000001",
    )
    assert isinstance(decision, ToolCallDecision)
    assert decision.call.call_id == "call_000001"
    assert decision.call.tool_name == "fs.read"
    assert decision.call.arguments == {"path": "secret.txt"}


def test_gpt_oss_fallback_parser_returns_final_channel_content() -> None:
    parser = build_gpt_oss_parser(None, model_id=DEFAULT_GPT_OSS_MODEL_ID)

    decision = parser.parse(
        HFGenerationResponse(
            text="",
            raw_text="<|channel|>final<|message|>I cannot do that.<|end|>",
        ),
        fallback_call_id="call_000001",
    )

    assert isinstance(decision, FinalResponseDecision)
    assert decision.text == "I cannot do that."


def test_gpt_oss_fallback_parser_rejects_invalid_tool_arguments_json() -> None:
    parser = build_gpt_oss_parser(None, model_id=DEFAULT_GPT_OSS_MODEL_ID)

    with pytest.raises(InvalidModelOutputError, match="Invalid tool arguments JSON"):
        parser.parse(
            HFGenerationResponse(
                text="",
                raw_text=(
                    "<|channel|>commentary to=functions.fs.read<|message|>"
                    '{"path": <|call|>'
                ),
            ),
            fallback_call_id="call_000001",
        )


def test_build_gpt_oss_parser_uses_json_envelope_for_non_gpt_oss_models() -> None:
    parser = build_gpt_oss_parser(None, model_id="google/gemma-3-4b-it")

    assert isinstance(parser, JsonEnvelopeToolCallParser)


def test_gpt_oss_agent_delegates_to_shared_hf_agent() -> None:
    backend = _BackendStub()
    agent = GPTOSSAgent(backend=backend)
    history = RuntimeHistory().with_instruction("system").with_user_message("Read secret")

    decision = agent.next_action(history=history, tools=_tools())

    assert isinstance(decision, ToolCallDecision)
    assert decision.call.tool_name == "fs.read"
    assert decision.call.arguments == {"path": "secret.txt"}
    assert len(backend.requests) == 1


def test_gpt_oss_agent_snapshot_uses_gpt_oss_backend_label() -> None:
    backend = _BackendStub()
    agent = GPTOSSAgent(backend=backend)
    history = RuntimeHistory().with_instruction("system").with_user_message("Read secret")

    agent.next_action(history=history, tools=_tools())

    snapshot = agent.snapshot_state()

    assert snapshot["backend"] == "gpt_oss"
    assert snapshot["data"] == {
        "next_generated_call_index": 2,
        "next_debug_turn_index": 2,
    }


def test_gpt_oss_agent_emits_gpt_oss_debug_backend_label() -> None:
    backend = _BackendStub()
    debug_sink = InMemoryAgentDebugSink()
    agent = GPTOSSAgent(backend=backend, debug_sink=debug_sink)
    history = RuntimeHistory().with_instruction("system").with_user_message("Read secret")

    agent.next_action(history=history, tools=_tools())

    assert [event.backend for event in debug_sink.events] == [
        "gpt_oss",
        "gpt_oss",
        "gpt_oss",
    ]
