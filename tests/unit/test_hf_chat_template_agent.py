from __future__ import annotations

import sys
from types import SimpleNamespace
from unittest.mock import Mock, call

import pytest

from aicomp_sdk.agents.debug import InMemoryAgentDebugSink
from aicomp_sdk.agents.hf_chat_template.agent import HFChatTemplateAgent
from aicomp_sdk.agents.hf_chat_template.backends.processor import (
    HFProcessorChatTemplateBackend,
)
from aicomp_sdk.agents.hf_chat_template.backends.llama_cpp import (
    LlamaCppChatTemplateBackend,
)
from aicomp_sdk.agents.hf_chat_template.backends.transformers import HFChatTemplateBackend
from aicomp_sdk.agents.hf_chat_template.response_parsing import (
    JsonEnvelopeToolCallParser,
    TokenizerNativeResponseParser,
    build_hf_response_parser,
)
from aicomp_sdk.agents.hf_chat_template.types import (
    HFBackendConfig,
    HFGenerationRequest,
    HFGenerationResponse,
    HFModelProfile,
    HFResponseParser,
)
from aicomp_sdk.agents.types import (
    AGENT_STATE_VERSION,
    AgentDecision,
    AgentStateVersionError,
    AgentToolSpec,
    FinalResponseDecision,
    InvalidModelOutputError,
    ToolCall,
    ToolCallDecision,
    ToolResult,
)
from aicomp_sdk.core.runtime_history import RuntimeHistory

# mypy: disable-error-code="arg-type"


def _backend_config(
    *,
    model_id: str = "openai/gpt-oss-20b",
    model_path: str | None = None,
    max_new_tokens: int = 256,
    tokenizer_kwargs: dict[str, object] | None = None,
    model_kwargs: dict[str, object] | None = None,
    trust_remote_code: bool | None = None,
    attn_implementation: str | None = None,
    generation_kwargs: dict[str, object] | None = None,
) -> HFBackendConfig:
    return HFBackendConfig(
        model_id=model_id,
        model_path=model_path,
        local_files_only=True,
        device_map="auto",
        torch_dtype="auto",
        tokenizer_kwargs=tokenizer_kwargs or {},
        model_kwargs=model_kwargs or {},
        trust_remote_code=trust_remote_code,
        attn_implementation=attn_implementation,
        max_new_tokens=max_new_tokens,
        generation_kwargs=generation_kwargs or {"do_sample": False},
    )


def _profile(
    *,
    chat_template: str | None = None,
    assistant_prefill: str | None = None,
    continue_final_message: bool = False,
) -> HFModelProfile:
    return HFModelProfile(
        instruction_role="system",
        chat_template=chat_template,
        assistant_prefill=assistant_prefill,
        continue_final_message=continue_final_message,
    )


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


class _RecordingBackend:
    def __init__(
        self,
        response: HFGenerationResponse,
        *,
        config: HFBackendConfig | None = None,
    ) -> None:
        self.response = response
        self.config = config or _backend_config()
        self.requests: list[HFGenerationRequest] = []

    def generate(self, request: HFGenerationRequest) -> HFGenerationResponse:
        self.requests.append(request)
        return self.response


class _SequentialBackend:
    def __init__(
        self,
        responses: list[HFGenerationResponse],
        *,
        config: HFBackendConfig | None = None,
    ) -> None:
        self.responses = list(responses)
        self.config = config or _backend_config()
        self.requests: list[HFGenerationRequest] = []

    def generate(self, request: HFGenerationRequest) -> HFGenerationResponse:
        self.requests.append(request)
        return self.responses.pop(0)


class _FakeLlama:
    def __init__(self, completion: object) -> None:
        self.completion = completion
        self.calls: list[dict[str, object]] = []
        self.closed = False

    def create_chat_completion(self, **kwargs: object) -> object:
        self.calls.append(kwargs)
        return self.completion

    def close(self) -> None:
        self.closed = True


class _StubParser(HFResponseParser):
    def __init__(self, decision: AgentDecision) -> None:
        self._decision = decision
        self.responses: list[tuple[HFGenerationResponse, str]] = []

    def parse(
        self,
        response: HFGenerationResponse,
        *,
        fallback_call_id: str,
    ) -> AgentDecision:
        self.responses.append((response, fallback_call_id))
        return self._decision


class _RaisingParser(HFResponseParser):
    def parse(
        self,
        response: HFGenerationResponse,
        *,
        fallback_call_id: str,
    ) -> AgentDecision:
        del response, fallback_call_id
        raise InvalidModelOutputError("bad parse")


class _FailOnceParser(HFResponseParser):
    def __init__(self, decision: AgentDecision) -> None:
        self._decision = decision
        self._failed = False

    def parse(
        self,
        response: HFGenerationResponse,
        *,
        fallback_call_id: str,
    ) -> AgentDecision:
        del response, fallback_call_id
        if not self._failed:
            self._failed = True
            raise InvalidModelOutputError("bad parse")
        return self._decision


def test_hf_backend_config_rejects_max_new_tokens_in_generation_kwargs() -> None:
    with pytest.raises(ValueError, match="max_new_tokens"):
        _backend_config(generation_kwargs={"max_new_tokens": 32})


def test_hf_backend_config_rejects_duplicate_loader_kwargs() -> None:
    with pytest.raises(ValueError, match="model_kwargs.*torch_dtype"):
        _backend_config(model_kwargs={"torch_dtype": "float16"})


def test_hf_model_profile_requires_continue_final_message_for_prefill() -> None:
    with pytest.raises(ValueError, match="assistant_prefill"):
        _profile(assistant_prefill='{"tool": ')


def test_hf_backend_from_pretrained_uses_config_kwargs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_tokenizer = Mock()
    mock_model = Mock()
    tokenizer_factory = Mock(return_value=mock_tokenizer)
    model_factory = Mock(return_value=mock_model)
    fake_module = SimpleNamespace(
        AutoTokenizer=SimpleNamespace(from_pretrained=tokenizer_factory),
        AutoModelForCausalLM=SimpleNamespace(from_pretrained=model_factory),
    )
    monkeypatch.setitem(sys.modules, "transformers", fake_module)
    config = _backend_config(
        model_path="/models/hf",
        tokenizer_kwargs={"padding_side": "left"},
        model_kwargs={"revision": "main"},
        trust_remote_code=True,
        attn_implementation="flash_attention_2",
    )

    backend = HFChatTemplateBackend.from_pretrained(config)

    assert backend.config == config
    tokenizer_factory.assert_called_once_with(
        "/models/hf",
        local_files_only=True,
        padding_side="left",
        trust_remote_code=True,
    )
    model_factory.assert_called_once_with(
        "/models/hf",
        torch_dtype="auto",
        device_map="auto",
        local_files_only=True,
        revision="main",
        trust_remote_code=True,
        attn_implementation="flash_attention_2",
    )


def test_hf_processor_backend_from_pretrained_uses_config_kwargs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_processor = Mock()
    mock_model = Mock()
    processor_factory = Mock(return_value=mock_processor)
    model_factory = Mock(return_value=mock_model)
    fake_module = SimpleNamespace(
        AutoProcessor=SimpleNamespace(from_pretrained=processor_factory),
        AutoModelForMultimodalLM=SimpleNamespace(from_pretrained=model_factory),
    )
    monkeypatch.setitem(sys.modules, "transformers", fake_module)
    config = _backend_config(
        model_path="/models/gemma4",
        tokenizer_kwargs={"padding_side": "left"},
        model_kwargs={"revision": "main"},
        trust_remote_code=True,
        attn_implementation="flash_attention_2",
    )

    backend = HFProcessorChatTemplateBackend.from_pretrained(config)

    assert backend.config == config
    assert backend.processor is mock_processor
    processor_factory.assert_called_once_with(
        "/models/gemma4",
        local_files_only=True,
        padding_side="left",
        trust_remote_code=True,
    )
    model_factory.assert_called_once_with(
        "/models/gemma4",
        dtype="auto",
        device_map="auto",
        local_files_only=True,
        revision="main",
        trust_remote_code=True,
        attn_implementation="flash_attention_2",
    )


def test_hf_backend_generate_forwards_request_and_decodes_suffix() -> None:
    mock_tokenizer = Mock()
    mock_model = Mock()
    mock_input_ids = Mock()
    mock_input_ids.shape = [1, 3]
    mock_inputs = Mock()
    mock_inputs.to.return_value = {"input_ids": mock_input_ids}
    mock_tokenizer.apply_chat_template.return_value = mock_inputs
    mock_model.device = "cpu"
    mock_model.generate.return_value = [[1, 2, 3, 4]]
    mock_tokenizer.decode.side_effect = [
        "<|channel|>final<|message|>done<|end|>",
        "done",
    ]
    backend = HFChatTemplateBackend(
        tokenizer=mock_tokenizer,
        model=mock_model,
        config=_backend_config(),
    )
    request = HFGenerationRequest(
        messages=[{"role": "user", "content": "Read secret"}],
        tools=[{"type": "function", "function": {"name": "fs.read"}}],
        chat_template="tool_use",
        add_generation_prompt=True,
        continue_final_message=False,
        max_new_tokens=64,
        generation_kwargs={"do_sample": False},
    )

    response = backend.generate(request)

    assert response.raw_text == "<|channel|>final<|message|>done<|end|>"
    assert response.text == "done"
    mock_tokenizer.apply_chat_template.assert_called_once()
    assert mock_tokenizer.apply_chat_template.call_args.args[0] == [
        {"role": "user", "content": "Read secret"}
    ]
    assert mock_tokenizer.apply_chat_template.call_args.kwargs == {
        "tools": [{"type": "function", "function": {"name": "fs.read"}}],
        "add_generation_prompt": True,
        "continue_final_message": False,
        "return_dict": True,
        "return_tensors": "pt",
        "chat_template": "tool_use",
    }
    mock_model.generate.assert_called_once_with(
        input_ids=mock_input_ids,
        do_sample=False,
        max_new_tokens=64,
    )
    assert mock_tokenizer.decode.call_args_list == [
        call(
            [4],
            skip_special_tokens=False,
            clean_up_tokenization_spaces=False,
        ),
        call(
            [4],
            skip_special_tokens=True,
            clean_up_tokenization_spaces=False,
        ),
    ]


def test_hf_processor_backend_generate_forwards_request_and_decodes_suffix() -> None:
    mock_processor = Mock()
    mock_model = Mock()
    mock_input_ids = Mock()
    mock_input_ids.shape = [1, 3]
    mock_inputs = Mock()
    mock_inputs.to.return_value = {"input_ids": mock_input_ids}
    mock_processor.apply_chat_template.return_value = "prompt"
    mock_processor.return_value = mock_inputs
    mock_model.device = "cpu"
    mock_model.generate.return_value = [[1, 2, 3, 4]]
    mock_processor.decode.side_effect = [
        '<|tool_call>call:fs.read{path:<|"|>a.txt<|"|>}<tool_call|>',
        "",
    ]
    backend = HFProcessorChatTemplateBackend(
        processor=mock_processor,
        model=mock_model,
        config=_backend_config(model_id="google/gemma-4-26B-A4B-it"),
    )
    request = HFGenerationRequest(
        messages=[{"role": "user", "content": "Read secret"}],
        tools=[{"type": "function", "function": {"name": "fs.read"}}],
        chat_template=None,
        add_generation_prompt=True,
        continue_final_message=False,
        max_new_tokens=64,
        generation_kwargs={"do_sample": False},
    )

    response = backend.generate(request)

    assert response.raw_text == '<|tool_call>call:fs.read{path:<|"|>a.txt<|"|>}<tool_call|>'
    assert response.text == ""
    mock_processor.apply_chat_template.assert_called_once_with(
        [{"role": "user", "content": "Read secret"}],
        tools=[{"type": "function", "function": {"name": "fs.read"}}],
        tokenize=False,
        add_generation_prompt=True,
    )
    mock_processor.assert_called_once_with(text="prompt", return_tensors="pt")
    mock_model.generate.assert_called_once_with(
        input_ids=mock_input_ids,
        do_sample=False,
        max_new_tokens=64,
    )
    assert mock_processor.decode.call_args_list == [
        call(
            [4],
            skip_special_tokens=False,
            clean_up_tokenization_spaces=False,
        ),
        call(
            [4],
            skip_special_tokens=True,
            clean_up_tokenization_spaces=False,
        ),
    ]


def test_llama_cpp_backend_from_model_path_uses_injected_llama_class() -> None:
    class FakeLlamaFactory:
        def __init__(self, **kwargs: object) -> None:
            self.kwargs = kwargs

    config = _backend_config(model_path="/models/hf")

    backend = LlamaCppChatTemplateBackend.from_model_path(
        model_path="/models/model.gguf",
        config=config,
        n_ctx=4096,
        n_gpu_layers=12,
        verbose=True,
        supports_tools=False,
        llama_cls=FakeLlamaFactory,
        llama_kwargs={"chat_format": "chatml"},
    )

    assert backend.config == config
    assert backend.supports_tools is False
    assert backend.llm.kwargs == {
        "model_path": "/models/model.gguf",
        "n_ctx": 4096,
        "n_gpu_layers": 12,
        "verbose": True,
        "chat_format": "chatml",
    }


def test_llama_cpp_backend_converts_request_for_chat_completion() -> None:
    llm = _FakeLlama(
        {
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": " done "},
                }
            ]
        }
    )
    backend = LlamaCppChatTemplateBackend(llm=llm, config=_backend_config())
    request = HFGenerationRequest(
        messages=[
            {"role": "user", "content": "Read the file"},
            {
                "role": "assistant",
                "tool_calls": [
                    {
                        "id": "call_1",
                        "function": {
                            "name": "fs.read",
                            "arguments": {"path": "a.txt"},
                        },
                    }
                ],
            },
            {
                "role": "tool",
                "name": "fs.read",
                "content": "A",
                "tool_call_id": "call_1",
            },
        ],
        tools=[{"type": "function", "function": {"name": "fs.read"}}],
        chat_template="ignored-by-llama-cpp",
        add_generation_prompt=True,
        continue_final_message=False,
        max_new_tokens=32,
        generation_kwargs={"do_sample": False, "top_p": 0.9},
    )

    response = backend.generate(request)

    assert response.text == "done"
    assert response.raw_text == " done "
    assert response.finish_reason == "stop"
    assert llm.calls == [
        {
            "messages": [
                {"role": "user", "content": "Read the file"},
                {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "function": {
                                "name": "fs.read",
                                "arguments": '{"path": "a.txt"}',
                            },
                            "type": "function",
                        }
                    ],
                },
                {
                    "role": "tool",
                    "content": "A",
                    "tool_call_id": "call_1",
                },
            ],
            "max_tokens": 32,
            "top_p": 0.9,
            "temperature": 0.0,
            "tools": [{"type": "function", "function": {"name": "fs.read"}}],
        }
    ]


def test_llama_cpp_backend_omits_tools_when_tool_forwarding_is_disabled() -> None:
    llm = _FakeLlama({"choices": [{"message": {"content": "done"}}]})
    backend = LlamaCppChatTemplateBackend(
        llm=llm,
        config=_backend_config(),
        supports_tools=False,
    )
    request = HFGenerationRequest(
        messages=[{"role": "user", "content": "Read the file"}],
        tools=[{"type": "function", "function": {"name": "fs.read"}}],
        chat_template=None,
        add_generation_prompt=True,
        continue_final_message=False,
        max_new_tokens=16,
        generation_kwargs={"do_sample": False},
    )

    backend.generate(request)

    assert "tools" not in llm.calls[0]


def test_llama_cpp_backend_extracts_parsed_tool_call_message() -> None:
    tool_calls = [
        {
            "id": "call_1",
            "type": "function",
            "function": {"name": "fs.read", "arguments": '{"path":"a.txt"}'},
        }
    ]
    llm = _FakeLlama(
        {
            "choices": [
                {
                    "finish_reason": "tool_calls",
                    "message": {"role": "assistant", "content": None, "tool_calls": tool_calls},
                }
            ]
        }
    )
    backend = LlamaCppChatTemplateBackend(llm=llm, config=_backend_config())
    request = HFGenerationRequest(
        messages=[{"role": "user", "content": "Read the file"}],
        tools=[],
        chat_template=None,
        add_generation_prompt=True,
        continue_final_message=False,
        max_new_tokens=16,
        generation_kwargs={},
    )

    response = backend.generate(request)

    assert response.text == ""
    assert response.raw_text == ""
    assert response.finish_reason == "tool_calls"
    assert response.parsed_response == {
        "role": "assistant",
        "content": "",
        "tool_calls": tool_calls,
    }


def test_llama_cpp_backend_rejects_malformed_completion() -> None:
    backend = LlamaCppChatTemplateBackend(
        llm=_FakeLlama({"choices": []}),
        config=_backend_config(),
    )
    request = HFGenerationRequest(
        messages=[{"role": "user", "content": "Read the file"}],
        tools=[],
        chat_template=None,
        add_generation_prompt=True,
        continue_final_message=False,
        max_new_tokens=16,
        generation_kwargs={},
    )

    with pytest.raises(ValueError, match="missing choices"):
        backend.generate(request)


def test_llama_cpp_backend_close_closes_llm_and_blocks_generation() -> None:
    llm = _FakeLlama({"choices": [{"message": {"content": "done"}}]})
    backend = LlamaCppChatTemplateBackend(llm=llm, config=_backend_config())
    request = HFGenerationRequest(
        messages=[{"role": "user", "content": "Read the file"}],
        tools=[],
        chat_template=None,
        add_generation_prompt=True,
        continue_final_message=False,
        max_new_tokens=16,
        generation_kwargs={},
    )

    backend.close()
    backend.close()

    assert llm.closed is True
    with pytest.raises(RuntimeError, match="closed"):
        backend.generate(request)


def test_hf_generation_request_rejects_conflicting_generation_flags() -> None:
    with pytest.raises(
        ValueError,
        match="cannot set both add_generation_prompt and continue_final_message",
    ):
        HFGenerationRequest(
            messages=[{"role": "user", "content": "Read secret"}],
            tools=[],
            chat_template=None,
            add_generation_prompt=True,
            continue_final_message=True,
            max_new_tokens=64,
            generation_kwargs={"do_sample": False},
        )


def test_hf_backend_from_pretrained_surfaces_transformers_import_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "transformers", SimpleNamespace())

    with pytest.raises(RuntimeError, match="Transformers SDK is not available"):
        HFChatTemplateBackend.from_pretrained(_backend_config(model_path="/models/hf"))


def test_hf_backend_from_pretrained_surfaces_model_load_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tokenizer_factory = Mock(side_effect=OSError("missing weights"))
    fake_module = SimpleNamespace(
        AutoTokenizer=SimpleNamespace(from_pretrained=tokenizer_factory),
        AutoModelForCausalLM=SimpleNamespace(from_pretrained=Mock()),
    )
    monkeypatch.setitem(sys.modules, "transformers", fake_module)

    with pytest.raises(
        RuntimeError,
        match="Failed to load HF chat-template backend from '/models/hf'",
    ):
        HFChatTemplateBackend.from_pretrained(_backend_config(model_path="/models/hf"))


def test_hf_agent_build_request_renders_history_tools_and_chat_template() -> None:
    backend = _RecordingBackend(
        HFGenerationResponse(text='{"final":"done"}', raw_text='{"final":"done"}'),
        config=_backend_config(max_new_tokens=128),
    )
    agent = HFChatTemplateAgent(
        backend=backend,
        profile=_profile(chat_template="tool_use"),
        parser=JsonEnvelopeToolCallParser(),
    )
    history = (
        RuntimeHistory()
        .with_instruction("system")
        .with_user_message("Read the file")
        .with_tool_request(ToolCall(call_id="call_1", tool_name="fs.read", arguments={"path": "a"}))
        .with_tool_result(
            ToolResult(
                call_id="call_1",
                tool_name="fs.read",
                output_text="A",
                is_error=False,
            )
        )
    )

    request = agent._build_request(history, _tools())

    assert request.messages == [
        {"role": "system", "content": "system"},
        {"role": "user", "content": "Read the file"},
        {
            "role": "assistant",
            "tool_calls": [
                {
                    "type": "function",
                    "function": {"name": "fs.read", "arguments": {"path": "a"}},
                    "id": "call_1",
                }
            ],
        },
        {
            "role": "tool",
            "name": "fs.read",
            "content": "A",
            "tool_call_id": "call_1",
        },
    ]
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
    assert request.chat_template == "tool_use"
    assert request.add_generation_prompt is True
    assert request.continue_final_message is False
    assert request.max_new_tokens == 128
    assert request.generation_kwargs == {"do_sample": False}


def test_hf_agent_build_request_uses_profile_driven_continue_final_message() -> None:
    backend = _RecordingBackend(HFGenerationResponse(text="done", raw_text="done"))
    agent = HFChatTemplateAgent(
        backend=backend,
        profile=_profile(
            assistant_prefill='{"tool": ',
            continue_final_message=True,
        ),
        parser=_StubParser(FinalResponseDecision(text="done")),
    )
    history = RuntimeHistory().with_instruction("system").with_user_message("Read it")

    request = agent._build_request(history, _tools())

    assert request.messages == [
        {"role": "system", "content": "system"},
        {"role": "user", "content": "Read it"},
        {"role": "assistant", "content": '{"tool": '},
    ]
    assert request.add_generation_prompt is False
    assert request.continue_final_message is True


def test_hf_agent_build_request_calls_custom_request_builder() -> None:
    backend = _RecordingBackend(HFGenerationResponse(text="done", raw_text="done"))
    history = RuntimeHistory().with_instruction("system").with_user_message("Read it")
    custom_request = HFGenerationRequest(
        messages=[{"role": "user", "content": "custom"}],
        tools=[],
        chat_template="custom",
        add_generation_prompt=True,
        continue_final_message=False,
        max_new_tokens=32,
        generation_kwargs={"do_sample": False},
    )
    request_builder = Mock(return_value=custom_request)
    agent = HFChatTemplateAgent(
        backend=backend,
        profile=_profile(),
        parser=_StubParser(FinalResponseDecision(text="done")),
        request_builder=request_builder,
    )

    request = agent._build_request(history, _tools())

    assert request is custom_request
    assert request_builder.call_args.kwargs == {
        "history": history,
        "tools": _tools(),
        "profile": _profile(),
        "backend": backend,
    }


def test_build_hf_response_parser_prefers_tokenizer_native_parser() -> None:
    tokenizer = SimpleNamespace(
        response_schema={"type": "json_schema"},
        parse_response=Mock(
            return_value={
                "content": "",
                "tool_calls": [
                    {
                        "type": "function",
                        "id": "native-call",
                        "function": {
                            "name": "fs.read",
                            "arguments": {"path": "secret.txt"},
                        },
                    }
                ],
            }
        ),
    )

    parser = build_hf_response_parser(tokenizer)

    assert isinstance(parser, TokenizerNativeResponseParser)
    decision = parser.parse(
        HFGenerationResponse(text="", raw_text="<raw>"),
        fallback_call_id="call_000001",
    )
    assert isinstance(decision, ToolCallDecision)
    assert decision.call.call_id == "native-call"
    assert decision.call.tool_name == "fs.read"
    assert decision.call.arguments == {"path": "secret.txt"}
    tokenizer.parse_response.assert_called_once_with("<raw>")


def test_build_hf_response_parser_falls_back_to_json_envelope_for_generic_models() -> None:
    parser = build_hf_response_parser(None)

    assert isinstance(parser, JsonEnvelopeToolCallParser)


def test_tokenizer_native_parser_fails_clearly_when_unsupported() -> None:
    parser = TokenizerNativeResponseParser(SimpleNamespace(parse_response=Mock()))

    with pytest.raises(InvalidModelOutputError, match="not supported"):
        parser.parse(
            HFGenerationResponse(text="done", raw_text="done"),
            fallback_call_id="call_000001",
        )


def test_tokenizer_native_parser_rejects_multiple_tool_calls() -> None:
    parser = TokenizerNativeResponseParser(
        SimpleNamespace(
            response_schema={"type": "json_schema"},
            parse_response=Mock(
                return_value={
                    "content": "",
                    "tool_calls": [
                        {
                            "type": "function",
                            "function": {
                                "name": "fs.read",
                                "arguments": {"path": "first.txt"},
                            },
                        },
                        {
                            "type": "function",
                            "function": {
                                "name": "fs.read",
                                "arguments": {"path": "second.txt"},
                            },
                        },
                    ],
                }
            ),
        )
    )

    with pytest.raises(InvalidModelOutputError, match="multiple tool calls"):
        parser.parse(
            HFGenerationResponse(text="", raw_text="<raw>"),
            fallback_call_id="call_000001",
        )


def test_json_envelope_tool_call_parser_handles_tool_call_response() -> None:
    parser = JsonEnvelopeToolCallParser()

    decision = parser.parse(
        HFGenerationResponse(
            text='{"tool":"fs.read","args":{"path":"secret.txt"}}',
            raw_text='{"tool":"fs.read","args":{"path":"secret.txt"}}',
        ),
        fallback_call_id="call_000001",
    )

    assert isinstance(decision, ToolCallDecision)
    assert decision.call.call_id == "call_000001"
    assert decision.call.tool_name == "fs.read"
    assert decision.call.arguments == {"path": "secret.txt"}


def test_json_envelope_tool_call_parser_handles_final_json_response() -> None:
    parser = JsonEnvelopeToolCallParser()

    decision = parser.parse(
        HFGenerationResponse(
            text='{"final":"done"}',
            raw_text='{"final":"done"}',
        ),
        fallback_call_id="call_000001",
    )

    assert decision == FinalResponseDecision(text="done")


def test_json_envelope_tool_call_parser_handles_plain_text_response() -> None:
    parser = JsonEnvelopeToolCallParser()

    decision = parser.parse(
        HFGenerationResponse(text="done", raw_text="done"),
        fallback_call_id="call_000001",
    )

    assert decision == FinalResponseDecision(text="done")


def test_hf_agent_prefers_backend_parsed_response() -> None:
    backend = _RecordingBackend(
        HFGenerationResponse(
            text="",
            raw_text="",
            parsed_response={
                "content": "",
                "tool_calls": [
                    {
                        "type": "function",
                        "id": "backend-call",
                        "function": {
                            "name": "fs.read",
                            "arguments": {"path": "secret.txt"},
                        },
                    }
                ],
            },
        )
    )
    fallback_parser = _StubParser(FinalResponseDecision(text="fallback"))
    agent = HFChatTemplateAgent(
        backend=backend,
        profile=_profile(),
        parser=fallback_parser,
    )
    history = RuntimeHistory().with_instruction("system").with_user_message("Read secret")

    decision = agent.next_action(history=history, tools=_tools())

    assert isinstance(decision, ToolCallDecision)
    assert decision.call.call_id == "backend-call"
    assert decision.call.tool_name == "fs.read"
    assert decision.call.arguments == {"path": "secret.txt"}
    assert fallback_parser.responses == []


def test_hf_agent_snapshot_restore_preserves_call_id_counter() -> None:
    backend = _SequentialBackend(
        [
            HFGenerationResponse(
                text='{"tool":"fs.read","args":{"path":"first.txt"}}',
                raw_text='{"tool":"fs.read","args":{"path":"first.txt"}}',
            ),
            HFGenerationResponse(
                text='{"tool":"fs.read","args":{"path":"second.txt"}}',
                raw_text='{"tool":"fs.read","args":{"path":"second.txt"}}',
            ),
        ]
    )
    restored_debug_sink = InMemoryAgentDebugSink()
    agent = HFChatTemplateAgent(
        backend=backend,
        profile=_profile(),
        parser=JsonEnvelopeToolCallParser(),
    )
    history = RuntimeHistory().with_instruction("system").with_user_message("Read secret")

    first = agent.next_action(history=history, tools=_tools())
    snapshot = agent.snapshot_state()
    restored_agent = HFChatTemplateAgent(
        backend=backend,
        profile=_profile(),
        parser=JsonEnvelopeToolCallParser(),
        debug_sink=restored_debug_sink,
    )
    restored_agent.restore_state(snapshot)
    second = restored_agent.next_action(history=history, tools=_tools())

    assert isinstance(first, ToolCallDecision)
    assert isinstance(second, ToolCallDecision)
    assert first.call.call_id == "call_000001"
    assert second.call.call_id == "call_000002"
    assert snapshot["data"] == {
        "next_generated_call_index": 2,
        "next_debug_turn_index": 2,
    }
    assert restored_debug_sink.events[0].turn_index == 2


def test_hf_agent_restore_rejects_invalid_generated_call_index() -> None:
    backend = _RecordingBackend(
        HFGenerationResponse(text='{"final":"done"}', raw_text='{"final":"done"}'),
    )
    agent = HFChatTemplateAgent(
        backend=backend,
        profile=_profile(),
        parser=JsonEnvelopeToolCallParser(),
    )

    with pytest.raises(
        AgentStateVersionError,
        match="next_generated_call_index must be >= 1",
    ):
        agent.restore_state(
            {
                "version": AGENT_STATE_VERSION,
                "backend": "hf_chat_template",
                "data": {
                    "next_generated_call_index": 0,
                    "next_debug_turn_index": 1,
                },
            }
        )


def test_hf_agent_restore_rejects_invalid_debug_turn_index() -> None:
    backend = _RecordingBackend(
        HFGenerationResponse(text='{"final":"done"}', raw_text='{"final":"done"}'),
    )
    agent = HFChatTemplateAgent(
        backend=backend,
        profile=_profile(),
        parser=JsonEnvelopeToolCallParser(),
    )

    with pytest.raises(
        AgentStateVersionError,
        match="next_debug_turn_index must be >= 1",
    ):
        agent.restore_state(
            {
                "version": AGENT_STATE_VERSION,
                "backend": "hf_chat_template",
                "data": {
                    "next_generated_call_index": 1,
                    "next_debug_turn_index": 0,
                },
            }
        )


def test_hf_agent_failed_next_action_does_not_advance_debug_turn_index() -> None:
    debug_sink = InMemoryAgentDebugSink()
    backend = _RecordingBackend(
        HFGenerationResponse(text='{"final":"done"}', raw_text='{"final":"done"}'),
    )
    agent = HFChatTemplateAgent(
        backend=backend,
        profile=_profile(),
        parser=JsonEnvelopeToolCallParser(),
        debug_sink=debug_sink,
    )
    invalid_history = RuntimeHistory(events=(object(),))
    valid_history = RuntimeHistory().with_instruction("system").with_user_message("Done")

    with pytest.raises(InvalidModelOutputError, match="Unsupported runtime event"):
        agent.next_action(history=invalid_history, tools=_tools())

    decision = agent.next_action(history=valid_history, tools=_tools())

    assert decision == FinalResponseDecision(text="done")
    assert [event.turn_index for event in debug_sink.events] == [1, 1, 1]


def test_hf_agent_emits_debug_events_for_successful_turn() -> None:
    debug_sink = InMemoryAgentDebugSink()
    backend = _RecordingBackend(
        HFGenerationResponse(text='{"final":"done"}', raw_text='{"final":"done"}'),
    )
    agent = HFChatTemplateAgent(
        backend=backend,
        profile=_profile(chat_template="tool_use"),
        parser=JsonEnvelopeToolCallParser(),
        debug_sink=debug_sink,
    )
    history = RuntimeHistory().with_instruction("system").with_user_message("Done")

    decision = agent.next_action(history=history, tools=_tools())

    assert decision == FinalResponseDecision(text="done")
    assert [event.phase for event in debug_sink.events] == [
        "request_built",
        "response_received",
        "decision_emitted",
    ]
    request_event = debug_sink.events[0]
    assert request_event.backend == "hf_chat_template"
    assert request_event.model == backend.config.model_source()
    assert request_event.provider_payload == {
        "chat_template": "tool_use",
        "generation_mode": {
            "add_generation_prompt": True,
            "continue_final_message": False,
        },
        "tool_names": ["fs.read"],
    }
    assert request_event.request_payload is not None
    assert request_event.request_payload["chat_template"] == "tool_use"
    assert debug_sink.events[1].response_payload == {
        "text": '{"final":"done"}',
        "raw_text": '{"final":"done"}',
        "finish_reason": None,
        "parsed_response": None,
    }
    assert debug_sink.events[2].decision_payload == {
        "type": "final_response",
        "text": "done",
    }


def test_hf_agent_emits_parse_error_debug_event() -> None:
    debug_sink = InMemoryAgentDebugSink()
    backend = _RecordingBackend(HFGenerationResponse(text="", raw_text=""))
    agent = HFChatTemplateAgent(
        backend=backend,
        profile=_profile(),
        parser=_RaisingParser(),
        debug_sink=debug_sink,
    )
    history = RuntimeHistory().with_instruction("system").with_user_message("Read")

    with pytest.raises(InvalidModelOutputError, match="bad parse"):
        agent.next_action(history=history, tools=_tools())

    assert [event.phase for event in debug_sink.events] == [
        "request_built",
        "response_received",
        "parse_error",
    ]
    assert debug_sink.events[2].error == "bad parse"
    assert debug_sink.events[2].response_payload == {
        "text": "",
        "raw_text": "",
        "finish_reason": None,
        "parsed_response": None,
    }
