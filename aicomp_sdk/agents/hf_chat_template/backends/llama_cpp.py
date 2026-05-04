from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, Self

from ..types import HFBackendConfig, HFGenerationRequest, HFGenerationResponse


class LlamaCppChatTemplateBackend:
    """llama.cpp implementation of the SDK chat-template generation backend."""

    def __init__(
        self,
        *,
        llm: Any,
        config: HFBackendConfig,
        supports_tools: bool = True,
    ) -> None:
        self.llm = llm
        self.config = config
        self.supports_tools = supports_tools

    @classmethod
    def from_model_path(
        cls,
        *,
        model_path: str,
        config: HFBackendConfig,
        n_ctx: int = 8192,
        n_gpu_layers: int = -1,
        verbose: bool = False,
        supports_tools: bool = True,
        llama_cls: Any | None = None,
        llama_kwargs: Mapping[str, Any] | None = None,
    ) -> Self:
        resolved_llama_cls = llama_cls
        if resolved_llama_cls is None:
            from llama_cpp import Llama

            resolved_llama_cls = Llama

        llm = resolved_llama_cls(
            model_path=model_path,
            n_ctx=n_ctx,
            n_gpu_layers=n_gpu_layers,
            verbose=verbose,
            **dict(llama_kwargs or {}),
        )
        return cls(llm=llm, config=config, supports_tools=supports_tools)

    def generate(self, request: HFGenerationRequest) -> HFGenerationResponse:
        if self.llm is None:
            raise RuntimeError("llama.cpp backend has been closed")

        completion_kwargs = self._build_completion_kwargs(request)
        completion = self.llm.create_chat_completion(**completion_kwargs)
        text, finish_reason, parsed_response = _extract_completion_response(completion)
        return HFGenerationResponse(
            text=text.strip(),
            raw_text=text,
            finish_reason=finish_reason,
            parsed_response=parsed_response,
        )

    def close(self) -> None:
        if self.llm is None:
            return
        close = getattr(self.llm, "close", None)
        if callable(close):
            close()
        self.llm = None

    def _build_completion_kwargs(self, request: HFGenerationRequest) -> dict[str, Any]:
        generation_kwargs = dict(request.generation_kwargs)
        do_sample = generation_kwargs.pop("do_sample", None)
        if do_sample is False and "temperature" not in generation_kwargs:
            generation_kwargs["temperature"] = 0.0

        completion_kwargs: dict[str, Any] = {
            "messages": _to_openai_chat_completion_messages(request.messages),
            "max_tokens": request.max_new_tokens,
        }
        completion_kwargs.update(generation_kwargs)
        if request.tools and self.supports_tools:
            completion_kwargs["tools"] = list(request.tools)
        return completion_kwargs


def _extract_completion_response(
    completion: Any,
) -> tuple[str, str | None, Mapping[str, Any] | None]:
    if not isinstance(completion, Mapping):
        raise ValueError("Invalid llama.cpp completion: expected object")

    choices = completion.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ValueError("Invalid llama.cpp completion: missing choices")

    choice = choices[0]
    if not isinstance(choice, Mapping):
        raise ValueError("Invalid llama.cpp completion choice")

    finish_reason = choice.get("finish_reason")
    resolved_finish_reason = finish_reason if isinstance(finish_reason, str) else None

    message = choice.get("message")
    if isinstance(message, Mapping):
        content = message.get("content")
        parsed_response = _extract_parsed_message(message)
        if content is None:
            return "", resolved_finish_reason, parsed_response
        return str(content), resolved_finish_reason, parsed_response

    text = choice.get("text")
    if text is None:
        return "", resolved_finish_reason, None
    return str(text), resolved_finish_reason, None


def _extract_parsed_message(message: Mapping[str, Any]) -> Mapping[str, Any] | None:
    tool_calls = message.get("tool_calls")
    content = message.get("content")
    if tool_calls is None:
        return None
    return {
        "role": "assistant",
        "content": content if isinstance(content, str) else "",
        "tool_calls": tool_calls,
    }


def _to_openai_chat_completion_messages(
    messages: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return [_to_openai_chat_completion_message(message) for message in messages]


def _to_openai_chat_completion_message(message: Mapping[str, Any]) -> dict[str, Any]:
    role = message.get("role")
    if role == "assistant" and message.get("tool_calls") is not None:
        normalized = dict(message)
        normalized["tool_calls"] = _to_openai_tool_calls(message["tool_calls"])
        return normalized
    if role == "tool":
        normalized = {
            "role": "tool",
            "content": message.get("content", ""),
        }
        tool_call_id = message.get("tool_call_id")
        if isinstance(tool_call_id, str) and tool_call_id:
            normalized["tool_call_id"] = tool_call_id
        return normalized
    return dict(message)


def _to_openai_tool_calls(raw_tool_calls: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_tool_calls, list):
        raise ValueError("llama.cpp chat history tool_calls must be a list")

    return [_to_openai_tool_call(tool_call) for tool_call in raw_tool_calls]


def _to_openai_tool_call(raw_tool_call: Any) -> dict[str, Any]:
    if not isinstance(raw_tool_call, Mapping):
        raise ValueError("llama.cpp chat history tool_call must be an object")

    normalized = dict(raw_tool_call)
    function_payload = normalized.get("function")
    if function_payload is not None:
        if not isinstance(function_payload, Mapping):
            raise ValueError("llama.cpp chat history tool_call function must be an object")
        normalized_function = dict(function_payload)
        if "arguments" in normalized_function:
            normalized_function["arguments"] = _to_openai_function_arguments(
                normalized_function["arguments"]
            )
        normalized["function"] = normalized_function
        normalized.setdefault("type", "function")
    return normalized


def _to_openai_function_arguments(raw_arguments: Any) -> str:
    if isinstance(raw_arguments, str):
        return raw_arguments
    if isinstance(raw_arguments, Mapping):
        return json.dumps(dict(raw_arguments), sort_keys=True)
    return json.dumps(raw_arguments, sort_keys=True)
