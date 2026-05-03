from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

from aicomp_sdk.agents.types import (
    AgentDecision,
    FinalResponseDecision,
    InvalidModelOutputError,
    JsonObject,
    ToolCall,
    ToolCallDecision,
)

from .types import HFGenerationResponse, HFResponseParser


class TokenizerNativeResponseParser(HFResponseParser):
    def __init__(self, tokenizer: Any) -> None:
        self._tokenizer = tokenizer

    def parse(
        self,
        response: HFGenerationResponse,
        *,
        fallback_call_id: str,
    ) -> AgentDecision:
        if not tokenizer_supports_response_parsing(self._tokenizer):
            raise InvalidModelOutputError(
                "Tokenizer-native response parsing is not supported for this tokenizer"
            )
        try:
            parsed_response = self._tokenizer.parse_response(response.raw_text)
        except Exception as err:
            raise InvalidModelOutputError("Tokenizer-native response parsing failed") from err
        return normalize_parsed_response(
            parsed_response,
            fallback_call_id=fallback_call_id,
        )


class JsonEnvelopeToolCallParser(HFResponseParser):
    def parse(
        self,
        response: HFGenerationResponse,
        *,
        fallback_call_id: str,
    ) -> AgentDecision:
        stripped = response.text.strip()
        if not stripped:
            raise InvalidModelOutputError("Model returned empty output")

        obj = _extract_top_level_json_object(stripped)
        if obj is None:
            return FinalResponseDecision(text=stripped)

        tool_name = _get_non_empty_string(obj.get("tool"))
        if tool_name is not None:
            return ToolCallDecision(
                call=ToolCall(
                    call_id=fallback_call_id,
                    tool_name=tool_name,
                    arguments=normalize_tool_arguments(obj.get("args", obj.get("arguments", {}))),
                )
            )

        has_args = "args" in obj or "arguments" in obj
        name = _get_non_empty_string(obj.get("name"))
        if name is not None and has_args:
            return ToolCallDecision(
                call=ToolCall(
                    call_id=fallback_call_id,
                    tool_name=name,
                    arguments=normalize_tool_arguments(obj.get("args", obj.get("arguments", {}))),
                )
            )

        final_text = obj.get("final")
        if isinstance(final_text, str):
            return FinalResponseDecision(text=final_text)

        return FinalResponseDecision(text=stripped)


def build_hf_response_parser(tokenizer: Any) -> HFResponseParser:
    if tokenizer_supports_response_parsing(tokenizer):
        return TokenizerNativeResponseParser(tokenizer)

    return JsonEnvelopeToolCallParser()


def normalize_parsed_response(
    parsed_response: Any,
    *,
    fallback_call_id: str,
) -> AgentDecision:
    if not isinstance(parsed_response, Mapping):
        raise InvalidModelOutputError("Parsed response must be an object")

    assistant_text = _normalize_assistant_text(parsed_response.get("content"))
    raw_tool_calls = parsed_response.get("tool_calls")
    if raw_tool_calls is not None:
        if not isinstance(raw_tool_calls, Sequence) or isinstance(raw_tool_calls, str):
            raise InvalidModelOutputError("Parsed tool calls must be a list")
        if len(raw_tool_calls) > 1:
            raise InvalidModelOutputError("Model returned multiple tool calls")
        if len(raw_tool_calls) == 1:
            return ToolCallDecision(
                call=_normalize_tool_call(
                    raw_tool_calls[0],
                    fallback_call_id=fallback_call_id,
                ),
                assistant_message=assistant_text or None,
            )

    if assistant_text:
        return FinalResponseDecision(text=assistant_text)

    raise InvalidModelOutputError("Parsed response produced neither assistant text nor tool call")


def normalize_tool_arguments(raw_arguments: Any) -> JsonObject:
    parsed_arguments = raw_arguments
    if isinstance(raw_arguments, str):
        try:
            parsed_arguments = json.loads(raw_arguments)
        except Exception as err:
            raise InvalidModelOutputError("Invalid tool arguments JSON") from err

    if not isinstance(parsed_arguments, dict):
        raise InvalidModelOutputError("Tool arguments must be an object")
    return parsed_arguments


def _get_non_empty_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def _extract_top_level_json_object(text: str) -> Mapping[str, object] | None:
    stripped = text.strip()
    if not stripped:
        return None

    decoder = json.JSONDecoder()
    try:
        value, end = decoder.raw_decode(stripped)
    except json.JSONDecodeError:
        return None

    if stripped[end:].strip():
        return None

    return value if isinstance(value, Mapping) else None


def tokenizer_supports_response_parsing(tokenizer: Any) -> bool:
    if tokenizer is None:
        return False
    if not callable(getattr(tokenizer, "parse_response", None)):
        return False
    return getattr(tokenizer, "response_schema", None) is not None


def _normalize_assistant_text(content: Any) -> str:
    if content is None:
        return ""
    if not isinstance(content, str):
        raise InvalidModelOutputError("Parsed assistant content must be a string")
    return content.strip()


def _normalize_tool_call(raw_tool_call: Any, *, fallback_call_id: str) -> ToolCall:
    if not isinstance(raw_tool_call, Mapping):
        raise InvalidModelOutputError("Parsed tool call must be an object")

    tool_type = raw_tool_call.get("type")
    if tool_type is not None and tool_type != "function":
        raise InvalidModelOutputError("Only function tool calls are supported")

    function_payload = raw_tool_call.get("function")
    if function_payload is not None:
        if not isinstance(function_payload, Mapping):
            raise InvalidModelOutputError("Parsed tool call function must be an object")
        tool_name = function_payload.get("name")
        raw_arguments = function_payload.get("arguments", {})
    else:
        tool_name = raw_tool_call.get("name") or raw_tool_call.get("tool")
        raw_arguments = raw_tool_call.get("arguments", raw_tool_call.get("args", {}))

    if not isinstance(tool_name, str) or not tool_name.strip():
        raise InvalidModelOutputError("Parsed tool call is missing a valid tool name")

    call_id = raw_tool_call.get("id")
    resolved_call_id = (
        str(call_id).strip() if isinstance(call_id, str) and call_id.strip() else fallback_call_id
    )
    return ToolCall(
        call_id=resolved_call_id,
        tool_name=tool_name,
        arguments=normalize_tool_arguments(raw_arguments),
    )
