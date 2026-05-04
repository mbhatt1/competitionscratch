from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any, Final

from aicomp_sdk.agents.debug import AgentDebugSink
from aicomp_sdk.agents.hf_chat_template.agent import (
    HFChatTemplateAgent,
    _build_default_hf_request,
    _relabel_hf_chat_template_snapshot,
    _unwrap_hf_chat_template_snapshot,
)
from aicomp_sdk.agents.hf_chat_template.backends.llama_cpp import (
    LlamaCppChatTemplateBackend,
)
from aicomp_sdk.agents.hf_chat_template.backends.processor import (
    HFProcessorChatTemplateBackend,
)
from aicomp_sdk.agents.hf_chat_template.backends.transformers import (
    _build_hf_backend_config,
)
from aicomp_sdk.agents.hf_chat_template.response_parsing import (
    normalize_parsed_response,
)
from aicomp_sdk.agents.hf_chat_template.types import (
    HFBackendConfig,
    HFGenerationBackendProtocol,
    HFGenerationRequest,
    HFGenerationResponse,
    HFModelProfile,
    HFResponseParser,
)
from aicomp_sdk.agents.protocol import AgentProtocol
from aicomp_sdk.agents.tool_specs import to_hf_function_tool
from aicomp_sdk.agents.types import (
    AgentDecision,
    AgentStateSnapshot,
    AgentToolSpec,
    AssistantMessageEvent,
    FinalResponseDecision,
    InstructionEvent,
    InvalidModelOutputError,
    JsonObject,
    JsonValue,
    ToolRequestEvent,
    ToolResultEvent,
    UserMessageEvent,
)
from aicomp_sdk.core.runtime_history import RuntimeHistory

DEFAULT_GEMMA4_MODEL_ID: Final[str] = "google/gemma-4-26B-A4B-it"


def build_gemma4_backend_config(
    *,
    model_path: str | None = None,
    model_id: str | None = None,
    local_files_only: bool = True,
    device_map: str = "auto",
    torch_dtype: str = "auto",
    tokenizer_kwargs: Mapping[str, Any] | None = None,
    model_kwargs: Mapping[str, Any] | None = None,
    trust_remote_code: bool | None = None,
    attn_implementation: str | None = None,
    max_new_tokens: int = 256,
    generation_kwargs: Mapping[str, Any] | None = None,
) -> HFBackendConfig:
    return _build_hf_backend_config(
        default_model_id=DEFAULT_GEMMA4_MODEL_ID,
        model_id_env_var="GEMMA4_MODEL_ID",
        model_path_env_var="GEMMA4_MODEL_PATH",
        model_path=model_path,
        model_id=model_id,
        local_files_only=local_files_only,
        device_map=device_map,
        torch_dtype=torch_dtype,
        tokenizer_kwargs=tokenizer_kwargs,
        model_kwargs=model_kwargs,
        trust_remote_code=trust_remote_code,
        attn_implementation=attn_implementation,
        max_new_tokens=max_new_tokens,
        generation_kwargs=generation_kwargs,
    )


def build_gemma4_backend(
    *,
    model_path: str | None = None,
    model_id: str | None = None,
    local_files_only: bool = True,
    device_map: str = "auto",
    torch_dtype: str = "auto",
    tokenizer_kwargs: Mapping[str, Any] | None = None,
    model_kwargs: Mapping[str, Any] | None = None,
    trust_remote_code: bool | None = None,
    attn_implementation: str | None = None,
    max_new_tokens: int = 256,
    generation_kwargs: Mapping[str, Any] | None = None,
) -> HFProcessorChatTemplateBackend:
    return HFProcessorChatTemplateBackend.from_pretrained(
        build_gemma4_backend_config(
            model_path=model_path,
            model_id=model_id,
            local_files_only=local_files_only,
            device_map=device_map,
            torch_dtype=torch_dtype,
            tokenizer_kwargs=tokenizer_kwargs,
            model_kwargs=model_kwargs,
            trust_remote_code=trust_remote_code,
            attn_implementation=attn_implementation,
            max_new_tokens=max_new_tokens,
            generation_kwargs=generation_kwargs,
        )
    )


def _build_gemma4_request(
    *,
    history: RuntimeHistory,
    tools: Sequence[AgentToolSpec],
    profile: HFModelProfile,
    backend: HFGenerationBackendProtocol,
) -> HFGenerationRequest:
    return HFGenerationRequest(
        messages=_render_gemma4_messages(history, profile=profile),
        tools=[to_hf_function_tool(tool) for tool in tools],
        chat_template=profile.chat_template,
        add_generation_prompt=True,
        continue_final_message=False,
        max_new_tokens=backend.config.max_new_tokens,
        generation_kwargs=dict(backend.config.generation_kwargs),
    )


def _render_gemma4_messages(
    history: RuntimeHistory,
    *,
    profile: HFModelProfile,
) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = []
    events = list(history.all_events())
    index = 0
    while index < len(events):
        event = events[index]
        if isinstance(event, InstructionEvent):
            messages.append({"role": profile.instruction_role, "content": event.text})
            index += 1
            continue
        if isinstance(event, UserMessageEvent):
            messages.append({"role": "user", "content": event.text})
            index += 1
            continue
        if isinstance(event, AssistantMessageEvent):
            messages.append({"role": "assistant", "content": event.text})
            index += 1
            continue
        if isinstance(event, ToolRequestEvent):
            message: dict[str, Any] = {
                "role": "assistant",
                "tool_calls": [
                    {
                        "function": {
                            "name": event.call.tool_name,
                            "arguments": dict(event.call.arguments),
                        }
                    }
                ],
            }
            next_event = events[index + 1] if index + 1 < len(events) else None
            if isinstance(next_event, ToolResultEvent):
                if (
                    next_event.result.call_id != event.call.call_id
                    or next_event.result.tool_name != event.call.tool_name
                ):
                    raise InvalidModelOutputError("Gemma 4 history has mismatched tool result")
                message["tool_responses"] = [
                    {
                        "name": next_event.result.tool_name,
                        "response": _parse_tool_response(next_event.result.output_text),
                    }
                ]
                next_next_event = events[index + 2] if index + 2 < len(events) else None
                if isinstance(next_next_event, AssistantMessageEvent):
                    message["content"] = next_next_event.text
                    index += 3
                else:
                    index += 2
            else:
                index += 1
            messages.append(message)
            continue
        if isinstance(event, ToolResultEvent):
            raise InvalidModelOutputError("Gemma 4 history has tool result without request")
        raise InvalidModelOutputError(f"Unsupported runtime event: {event!r}")
    return messages


def _parse_tool_response(output_text: str) -> object:
    try:
        return json.loads(output_text)
    except json.JSONDecodeError:
        return output_text


def build_gemma4_parser(parser_source: Any, *, model_id: str) -> HFResponseParser:
    del model_id
    if callable(getattr(parser_source, "parse_response", None)):
        return Gemma4NativeResponseParser(parser_source)

    tokenizer = getattr(parser_source, "tokenizer", None)
    if callable(getattr(tokenizer, "parse_response", None)):
        return Gemma4NativeResponseParser(tokenizer)

    return Gemma4ToolCallParser()


class Gemma4NativeResponseParser(HFResponseParser):
    def __init__(self, parser_source: Any) -> None:
        self._parser_source = parser_source

    def parse(
        self,
        response: HFGenerationResponse,
        *,
        fallback_call_id: str,
    ) -> AgentDecision:
        try:
            parsed_response = self._parser_source.parse_response(response.raw_text)
        except Exception as err:
            raise InvalidModelOutputError("Gemma 4 native response parsing failed") from err
        return normalize_parsed_response(
            parsed_response,
            fallback_call_id=fallback_call_id,
        )


class Gemma4ToolCallParser(HFResponseParser):
    def parse(
        self,
        response: HFGenerationResponse,
        *,
        fallback_call_id: str,
    ) -> AgentDecision:
        parsed_response = _parse_gemma4_tool_call_response(
            response.raw_text,
            assistant_text=response.text,
        )
        if parsed_response is not None:
            return normalize_parsed_response(
                parsed_response,
                fallback_call_id=fallback_call_id,
            )

        stripped = response.text.strip()
        if stripped:
            return FinalResponseDecision(text=stripped)
        raise InvalidModelOutputError("Model returned empty output")


class Gemma4Agent(AgentProtocol):
    """Gemma 4 agent implemented via native HF tool-call chat templates."""

    def __init__(
        self,
        backend: HFGenerationBackendProtocol | None = None,
        *,
        profile: HFModelProfile | None = None,
        parser: HFResponseParser | None = None,
        debug_sink: AgentDebugSink | None = None,
    ) -> None:
        resolved_backend = backend or build_gemma4_backend()
        resolved_profile = profile or HFModelProfile(instruction_role="system")
        resolved_parser = parser or build_gemma4_parser(
            getattr(resolved_backend, "processor", None),
            model_id=resolved_backend.config.model_id,
        )
        request_builder = _build_gemma4_request
        if isinstance(resolved_backend, LlamaCppChatTemplateBackend):
            request_builder = _build_default_hf_request
        self._delegate = HFChatTemplateAgent(
            backend=resolved_backend,
            profile=resolved_profile,
            parser=resolved_parser,
            request_builder=request_builder,
            debug_sink=debug_sink,
            debug_backend_label="gemma_4",
        )

    def next_action(
        self,
        *,
        history: RuntimeHistory,
        tools: Sequence[AgentToolSpec],
    ) -> AgentDecision:
        return self._delegate.next_action(history=history, tools=tools)

    def reset_state(self) -> None:
        self._delegate.reset_state()

    def snapshot_state(self) -> AgentStateSnapshot:
        return _relabel_hf_chat_template_snapshot(
            self._delegate.snapshot_state(),
            backend_label="gemma_4",
        )

    def restore_state(self, snapshot: AgentStateSnapshot) -> None:
        self._delegate.restore_state(
            _unwrap_hf_chat_template_snapshot(
                snapshot,
                backend_label="gemma_4",
            )
        )


def _parse_gemma4_tool_call_response(
    raw_text: str,
    *,
    assistant_text: str,
) -> dict[str, Any] | None:
    if not raw_text.strip():
        return None

    tool_calls: list[dict[str, Any]] = []
    for match in _GEMMA4_TOOL_CALL_PATTERN.finditer(raw_text):
        arguments = _parse_gemma4_arguments(match.group("arguments"))
        tool_calls.append(
            {
                "type": "function",
                "function": {
                    "name": match.group("name"),
                    "arguments": arguments,
                },
            }
        )

    if not tool_calls:
        return None

    return {
        "role": "assistant",
        "content": _clean_fallback_assistant_text(assistant_text),
        "tool_calls": tool_calls,
    }


def _clean_fallback_assistant_text(text: str) -> str:
    stripped = text.strip()
    if "<|tool_call>" in stripped or "<tool_call|>" in stripped:
        return ""
    return stripped


def _parse_gemma4_arguments(args_blob: str) -> JsonObject:
    arguments: dict[str, JsonValue] = {}
    position = 0
    while position < len(args_blob):
        match = _GEMMA4_ARGUMENT_PATTERN.match(args_blob, position)
        if match is None:
            raise InvalidModelOutputError("Invalid Gemma 4 tool-call arguments")

        value = match.group("quoted")
        if value is None:
            value = match.group("bare") or ""
        arguments[match.group("key")] = _cast_gemma4_argument(value)

        position = match.end()
        if position == len(args_blob):
            break
        if args_blob[position] != ",":
            raise InvalidModelOutputError("Invalid Gemma 4 tool-call argument separator")
        position += 1
    return arguments


def _cast_gemma4_argument(value: str) -> JsonValue:
    stripped = value.strip().strip("'\"")
    lowered = stripped.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if lowered == "null":
        return None

    try:
        return int(stripped)
    except ValueError:
        pass

    try:
        return float(stripped)
    except ValueError:
        pass

    return stripped


_GEMMA4_TOOL_CALL_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"<\|tool_call>call:(?P<name>[A-Za-z0-9_.-]+)\{" r"(?P<arguments>.*?)" r"\}<tool_call\|>",
    re.DOTALL,
)
_GEMMA4_ARGUMENT_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?P<key>[A-Za-z_][A-Za-z0-9_.-]*):" r"(?:<\|\"\|>(?P<quoted>.*?)<\|\"\|>|(?P<bare>[^,}]*))",
    re.DOTALL,
)
