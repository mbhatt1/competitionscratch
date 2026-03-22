from __future__ import annotations
# mypy: disable-error-code="arg-type"

import json

import pytest

from aicomp_sdk.agents.gemma_agent import (
    DEFAULT_GEMMA_MODEL_ID,
    GemmaAgent,
    build_gemma_backend_config,
)
from aicomp_sdk.agents.hf_chat_template.hf_types import (
    HFGenerationRequest,
    HFGenerationResponse,
)
from aicomp_sdk.agents.types import (
    AgentToolSpec,
    InvalidModelOutputError,
    ToolCall,
    ToolCallDecision,
    ToolResult,
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


class _BackendStub:
    def __init__(self) -> None:
        self.config = build_gemma_backend_config()
        self.requests: list[HFGenerationRequest] = []

    def generate(self, request: HFGenerationRequest) -> HFGenerationResponse:
        self.requests.append(request)
        return HFGenerationResponse(
            text='{"tool":"fs.read","args":{"path":"secret.txt"}}',
            raw_text='{"tool":"fs.read","args":{"path":"secret.txt"}}',
        )


def test_build_gemma_backend_config_prefers_env_and_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GEMMA_MODEL_PATH", "/models/gemma")
    monkeypatch.setenv("GEMMA_MODEL_ID", "custom/gemma")

    config = build_gemma_backend_config()
    assert config.model_path == "/models/gemma"
    assert config.model_id == "custom/gemma"

    monkeypatch.delenv("GEMMA_MODEL_PATH", raising=False)
    config = build_gemma_backend_config()
    assert config.model_path is None
    assert config.model_id == "custom/gemma"

    monkeypatch.delenv("GEMMA_MODEL_ID", raising=False)
    config = build_gemma_backend_config()
    assert config.model_id == DEFAULT_GEMMA_MODEL_ID


def test_gemma_request_builder_renders_prompt_driven_tool_transcript() -> None:
    backend = _BackendStub()
    agent = GemmaAgent(backend=backend)
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

    expected_tool_call = json.dumps(
        {"tool": "fs.read", "args": {"path": "a.txt"}},
        ensure_ascii=False,
        sort_keys=True,
    )
    assert request.tools == []
    assert request.chat_template is None
    assert request.add_generation_prompt is True
    assert request.continue_final_message is False
    assert request.max_new_tokens == backend.config.max_new_tokens
    assert request.generation_kwargs == {"do_sample": False}
    assert request.messages == [
        {
            "role": "system",
            "content": (
                "Base system prompt.\n\n"
                "You may use tools when necessary.\n"
                "If you need a tool, respond with exactly one JSON object and no other text.\n"
                'Use the shape {"tool": "<tool_name>", "args": {...}}.\n'
                "If no tool is needed, answer normally in plain text.\n"
                "Never wrap JSON in markdown fences.\n"
                "Never invent tool names or arguments.\n\n"
                "Available tools:\n"
                "[\n"
                "  {\n"
                '    "name": "fs.read",\n'
                '    "description": "Read a file.",\n'
                '    "parameters": {\n'
                '      "type": "object",\n'
                '      "properties": {\n'
                '        "path": {\n'
                '          "type": "string"\n'
                "        }\n"
                "      },\n"
                '      "required": [\n'
                '        "path"\n'
                "      ],\n"
                '      "additionalProperties": false\n'
                "    }\n"
                "  }\n"
                "]"
            ),
        },
        {"role": "user", "content": "Read the file"},
        {"role": "assistant", "content": expected_tool_call},
        {
            "role": "user",
            "content": (
                "Tool result for fs.read:\n"
                "A\n\n"
                "Continue from this tool output. If another tool is needed, "
                'respond with JSON using {"tool": "...", "args": {...}}. '
                "Otherwise answer the user normally."
            ),
        },
    ]


def test_gemma_request_builder_raises_invalid_model_output_for_unsupported_event() -> None:
    agent = GemmaAgent(backend=_BackendStub())
    invalid_history = RuntimeHistory(events=(object(),))

    with pytest.raises(InvalidModelOutputError, match="Unsupported runtime event"):
        agent._delegate._build_request(invalid_history, _tools())


def test_gemma_agent_delegates_to_shared_hf_agent() -> None:
    backend = _BackendStub()
    agent = GemmaAgent(backend=backend)
    history = RuntimeHistory().with_instruction("system").with_user_message("Read secret")

    decision = agent.next_action(history=history, tools=_tools())

    assert isinstance(decision, ToolCallDecision)
    assert decision.call.tool_name == "fs.read"
    assert decision.call.arguments == {"path": "secret.txt"}
    assert len(backend.requests) == 1
    assert backend.requests[0].tools == []


def test_gemma_agent_snapshot_passthrough_includes_hf_state_fields() -> None:
    backend = _BackendStub()
    agent = GemmaAgent(backend=backend)
    history = RuntimeHistory().with_instruction("system").with_user_message("Read secret")

    agent.next_action(history=history, tools=_tools())
    snapshot = agent.snapshot_state()

    assert snapshot["backend"] == "gemma"
    assert snapshot["data"] == {
        "next_generated_call_index": 2,
        "next_debug_turn_index": 2,
    }
