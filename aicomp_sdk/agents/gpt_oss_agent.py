from __future__ import annotations

import re
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
    TokenizerNativeResponseParser,
    normalize_parsed_response,
    normalize_tool_arguments,
    tokenizer_supports_response_parsing,
)
from aicomp_sdk.agents.hf_chat_template.types import (
    HFBackendConfig,
    HFGenerationBackendProtocol,
    HFGenerationResponse,
    HFModelProfile,
    HFResponseParser,
)
from aicomp_sdk.agents.protocol import AgentProtocol
from aicomp_sdk.agents.types import (
    AgentDecision,
    AgentStateSnapshot,
    AgentToolSpec,
    FinalResponseDecision,
    InvalidModelOutputError,
)
from aicomp_sdk.core.runtime_history import RuntimeHistory

DEFAULT_GPT_OSS_MODEL_ID: Final[str] = "openai/gpt-oss-20b"


def build_gpt_oss_backend_config(
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
        default_model_id=DEFAULT_GPT_OSS_MODEL_ID,
        model_id_env_var="GPT_OSS_MODEL_ID",
        model_path_env_var="GPT_OSS_MODEL_PATH",
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


def build_gpt_oss_backend(
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
        build_gpt_oss_backend_config(
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


def build_gpt_oss_parser(tokenizer: Any, *, model_id: str) -> HFResponseParser:
    if tokenizer_supports_response_parsing(tokenizer):
        return TokenizerNativeResponseParser(tokenizer)

    normalized_model_id = model_id.lower().replace("_", "-")
    if "gpt-oss" in normalized_model_id:
        return GptOssHarmonyResponseParser()

    return JsonEnvelopeToolCallParser()


class GptOssHarmonyResponseParser(HFResponseParser):
    def parse(
        self,
        response: HFGenerationResponse,
        *,
        fallback_call_id: str,
    ) -> AgentDecision:
        parsed_response = _parse_gpt_oss_harmony_response(response.raw_text)
        if parsed_response is not None:
            return normalize_parsed_response(
                parsed_response,
                fallback_call_id=fallback_call_id,
            )

        stripped = response.text.strip()
        if stripped:
            return FinalResponseDecision(text=stripped)
        raise InvalidModelOutputError("Model returned empty output")


class GPTOSSAgent(AgentProtocol):
    """GPT-OSS agent implemented via the shared HF chat-template adapter."""

    def __init__(
        self,
        backend: HFGenerationBackendProtocol | None = None,
        *,
        profile: HFModelProfile | None = None,
        parser: HFResponseParser | None = None,
        debug_sink: AgentDebugSink | None = None,
    ) -> None:
        resolved_backend = backend or build_gpt_oss_backend()
        resolved_profile = profile or HFModelProfile(instruction_role="system")
        resolved_parser = parser or build_gpt_oss_parser(
            getattr(resolved_backend, "tokenizer", None),
            model_id=resolved_backend.config.model_id,
        )
        self._delegate = HFChatTemplateAgent(
            backend=resolved_backend,
            profile=resolved_profile,
            parser=resolved_parser,
            debug_sink=debug_sink,
            debug_backend_label="gpt_oss",
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
            backend_label="gpt_oss",
        )

    def restore_state(self, snapshot: AgentStateSnapshot) -> None:
        self._delegate.restore_state(
            _unwrap_hf_chat_template_snapshot(
                snapshot,
                backend_label="gpt_oss",
            )
        )


def _parse_gpt_oss_harmony_response(raw_text: str) -> dict[str, Any] | None:
    if not raw_text.strip():
        return None

    tool_calls: list[dict[str, Any]] = []
    for match in _GPT_OSS_TOOL_CALL_PATTERN.finditer(raw_text):
        header = match.group("header")
        tool_match = re.search(r"to=functions\.([A-Za-z0-9_.-]+)", header)
        if tool_match is None:
            raise InvalidModelOutputError("GPT-OSS tool call output is missing a function target")
        arguments = normalize_tool_arguments(match.group("arguments").strip())
        tool_calls.append(
            {
                "type": "function",
                "function": {
                    "name": tool_match.group(1),
                    "arguments": arguments,
                },
            }
        )

    content_chunks = [
        match.group("content").strip()
        for match in _GPT_OSS_FINAL_MESSAGE_PATTERN.finditer(raw_text)
        if match.group("content").strip()
    ]
    content = "\n".join(content_chunks)

    if not tool_calls and not content:
        return None

    return {
        "role": "assistant",
        "content": content,
        "tool_calls": tool_calls,
    }


_GPT_OSS_TOOL_CALL_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"<\|channel\|>commentary(?P<header>.*?)<\|message\|>"
    r"(?P<arguments>.*?)(?:<\|call\|>|<\|end\|>|$)",
    re.DOTALL,
)
_GPT_OSS_FINAL_MESSAGE_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"<\|channel\|>final<\|message\|>(?P<content>.*?)(?:<\|end\|>|$)",
    re.DOTALL,
)
