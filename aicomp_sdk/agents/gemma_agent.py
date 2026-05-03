from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any, Final

from aicomp_sdk.agents.debug import AgentDebugSink
from aicomp_sdk.agents.hf_chat_template.agent import (
    HFChatTemplateAgent,
    _relabel_hf_chat_template_snapshot,
    _unwrap_hf_chat_template_snapshot,
)
from aicomp_sdk.agents.hf_chat_template.backends.transformers import (
    HFChatTemplateBackend,
    _build_hf_backend_config,
)
from aicomp_sdk.agents.hf_chat_template.response_parsing import (
    JsonEnvelopeToolCallParser,
)
from aicomp_sdk.agents.hf_chat_template.types import (
    HFBackendConfig,
    HFGenerationBackendProtocol,
    HFGenerationRequest,
    HFModelProfile,
    HFRequestBuilder,
    HFResponseParser,
)
from aicomp_sdk.agents.protocol import AgentProtocol
from aicomp_sdk.agents.types import (
    AgentDecision,
    AgentStateSnapshot,
    AgentToolSpec,
    AssistantMessageEvent,
    InstructionEvent,
    InvalidModelOutputError,
    ToolRequestEvent,
    ToolResultEvent,
    UserMessageEvent,
)
from aicomp_sdk.core.runtime_history import RuntimeHistory

DEFAULT_GEMMA_MODEL_ID: Final[str] = "google/gemma-3-4b-it"


def build_gemma_backend_config(
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
        default_model_id=DEFAULT_GEMMA_MODEL_ID,
        model_id_env_var="GEMMA_MODEL_ID",
        model_path_env_var="GEMMA_MODEL_PATH",
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


def build_gemma_backend(
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
) -> HFChatTemplateBackend:
    return HFChatTemplateBackend.from_pretrained(
        build_gemma_backend_config(
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


def _build_gemma_request(
    *,
    history: RuntimeHistory,
    tools: Sequence[AgentToolSpec],
    profile: HFModelProfile,
    backend: HFGenerationBackendProtocol,
) -> HFGenerationRequest:
    return HFGenerationRequest(
        messages=_render_gemma_messages(history, profile=profile, tools=tools),
        tools=[],
        chat_template=profile.chat_template,
        add_generation_prompt=True,
        continue_final_message=False,
        max_new_tokens=backend.config.max_new_tokens,
        generation_kwargs=dict(backend.config.generation_kwargs),
    )


def _render_gemma_messages(
    history: RuntimeHistory,
    *,
    profile: HFModelProfile,
    tools: Sequence[AgentToolSpec],
) -> list[dict[str, Any]]:
    system_chunks = [event.text.strip() for event in history.instructions if event.text.strip()]
    tool_instructions = _build_gemma_tool_instructions(tools)
    if tool_instructions:
        system_chunks.append(tool_instructions)

    messages: list[dict[str, Any]] = []
    if system_chunks:
        messages.append(
            {
                "role": profile.instruction_role,
                "content": "\n\n".join(system_chunks),
            }
        )

    for event in history.events:
        if isinstance(event, UserMessageEvent):
            messages.append({"role": "user", "content": event.text})
            continue
        if isinstance(event, AssistantMessageEvent):
            messages.append({"role": "assistant", "content": event.text})
            continue
        if isinstance(event, ToolRequestEvent):
            messages.append(
                {
                    "role": "assistant",
                    "content": json.dumps(
                        {
                            "tool": event.call.tool_name,
                            "args": dict(event.call.arguments),
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                    ),
                }
            )
            continue
        if isinstance(event, ToolResultEvent):
            result_label = "error" if event.result.is_error else "result"
            messages.append(
                {
                    "role": "user",
                    "content": (
                        f"Tool {result_label} for {event.result.tool_name}:\n"
                        f"{event.result.output_text}\n\n"
                        "Continue from this tool output. If another tool is needed, "
                        'respond with JSON using {"tool": "...", "args": {...}}. '
                        "Otherwise answer the user normally."
                    ),
                }
            )
            continue
        if isinstance(event, InstructionEvent):
            continue
        raise InvalidModelOutputError(f"Unsupported runtime event: {event!r}")
    return messages


def _build_gemma_tool_instructions(tools: Sequence[AgentToolSpec]) -> str:
    if not tools:
        return ""

    tool_descriptors = [
        {
            "name": tool.name,
            "description": tool.description,
            "parameters": tool.parameters_json_schema,
        }
        for tool in tools
    ]
    return (
        "You may use tools when necessary.\n"
        "If you need a tool, respond with exactly one JSON object and no other text.\n"
        'Use the shape {"tool": "<tool_name>", "args": {...}}.\n'
        "If no tool is needed, answer normally in plain text.\n"
        "Never wrap JSON in markdown fences.\n"
        "Never invent tool names or arguments.\n\n"
        f"Available tools:\n{json.dumps(tool_descriptors, ensure_ascii=False, indent=2)}"
    )


class GemmaAgent(AgentProtocol):
    """Gemma agent implemented via prompt-driven tool use on the shared HF adapter."""

    def __init__(
        self,
        backend: HFGenerationBackendProtocol | None = None,
        *,
        profile: HFModelProfile | None = None,
        parser: HFResponseParser | None = None,
        request_builder: HFRequestBuilder | None = None,
        debug_sink: AgentDebugSink | None = None,
    ) -> None:
        resolved_backend = backend or build_gemma_backend()
        resolved_profile = profile or HFModelProfile(instruction_role="system")
        resolved_parser = parser or JsonEnvelopeToolCallParser()
        self._delegate = HFChatTemplateAgent(
            backend=resolved_backend,
            profile=resolved_profile,
            parser=resolved_parser,
            request_builder=request_builder or _build_gemma_request,
            debug_sink=debug_sink,
            debug_backend_label="gemma",
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
            backend_label="gemma",
        )

    def restore_state(self, snapshot: AgentStateSnapshot) -> None:
        self._delegate.restore_state(
            _unwrap_hf_chat_template_snapshot(
                snapshot,
                backend_label="gemma",
            )
        )
