from __future__ import annotations

import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Self

from aicomp_sdk.agents.debug import (
    AgentDebugEvent,
    AgentDebugSink,
    DebugPhase,
    make_json_safe,
    serialize_agent_decision,
    summarize_runtime_history,
)
from aicomp_sdk.agents.protocol import AgentProtocol
from aicomp_sdk.agents.tool_specs import to_hf_function_tool
from aicomp_sdk.agents.types import (
    AGENT_STATE_VERSION,
    AgentDecision,
    AgentStateSnapshot,
    AgentStateVersionError,
    AgentToolSpec,
    AssistantMessageEvent,
    InstructionEvent,
    InvalidModelOutputError,
    JsonObject,
    ToolCallDecision,
    ToolRequestEvent,
    ToolResultEvent,
    UserMessageEvent,
)
from aicomp_sdk.core.runtime_history import RuntimeHistory

from .response_parsing import normalize_parsed_response
from .types import (
    HFGenerationBackendProtocol,
    HFGenerationRequest,
    HFGenerationResponse,
    HFModelProfile,
    HFRequestBuilder,
    HFResponseParser,
)


@dataclass(frozen=True)
class HFChatTemplateAgentState:
    next_generated_call_index: int = 1
    next_debug_turn_index: int = 1

    def __post_init__(self) -> None:
        if self.next_generated_call_index < 1:
            raise ValueError("next_generated_call_index must be >= 1")
        if self.next_debug_turn_index < 1:
            raise ValueError("next_debug_turn_index must be >= 1")

    def advance(self, decision: AgentDecision) -> Self:
        next_generated_call_index = self.next_generated_call_index
        if isinstance(decision, ToolCallDecision):
            next_generated_call_index += 1
        return type(self)(
            next_generated_call_index=next_generated_call_index,
            next_debug_turn_index=self.next_debug_turn_index + 1,
        )

    @classmethod
    def from_snapshot_data(cls, data: object) -> Self:
        if not isinstance(data, Mapping):
            raise AgentStateVersionError("Invalid agent snapshot data: expected object")
        try:
            return cls(
                next_generated_call_index=cls._require_positive_int(
                    data,
                    key="next_generated_call_index",
                ),
                next_debug_turn_index=cls._require_positive_int(
                    data,
                    key="next_debug_turn_index",
                ),
            )
        except ValueError as err:
            raise AgentStateVersionError(f"Invalid agent snapshot state: {err}") from err

    @staticmethod
    def _require_positive_int(data: Mapping[str, object], *, key: str) -> int:
        if key not in data:
            raise ValueError(f"missing {key}")
        value = data[key]
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{key} must be an integer")
        if value < 1:
            raise ValueError(f"{key} must be >= 1")
        return value


def _build_default_hf_request(
    *,
    history: RuntimeHistory,
    tools: Sequence[AgentToolSpec],
    profile: HFModelProfile,
    backend: HFGenerationBackendProtocol,
) -> HFGenerationRequest:
    messages = _render_hf_messages(history, profile=profile)
    continue_final_message = profile.continue_final_message
    if continue_final_message:
        messages = _with_assistant_prefill(
            messages,
            profile.assistant_prefill or "",
        )

    return HFGenerationRequest(
        messages=messages,
        tools=_render_hf_tools(tools),
        chat_template=profile.chat_template,
        add_generation_prompt=not continue_final_message,
        continue_final_message=continue_final_message,
        max_new_tokens=backend.config.max_new_tokens,
        generation_kwargs=dict(backend.config.generation_kwargs),
    )


def _render_hf_messages(
    history: RuntimeHistory,
    *,
    profile: HFModelProfile,
) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = []
    for event in history.all_events():
        if isinstance(event, InstructionEvent):
            messages.append({"role": profile.instruction_role, "content": event.text})
            continue
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
                    "tool_calls": [
                        {
                            "type": "function",
                            "function": {
                                "name": event.call.tool_name,
                                "arguments": event.call.arguments,
                            },
                            "id": event.call.call_id,
                        }
                    ],
                }
            )
            continue
        if isinstance(event, ToolResultEvent):
            messages.append(
                {
                    "role": "tool",
                    "name": event.result.tool_name,
                    "content": event.result.output_text,
                    "tool_call_id": event.result.call_id,
                }
            )
            continue
        raise InvalidModelOutputError(f"Unsupported runtime event: {event!r}")
    return messages


def _render_hf_tools(tools: Sequence[AgentToolSpec]) -> list[JsonObject]:
    return [to_hf_function_tool(spec) for spec in tools]


def _with_assistant_prefill(
    messages: list[dict[str, Any]],
    assistant_prefill: str,
) -> list[dict[str, Any]]:
    rendered_messages = [dict(message) for message in messages]
    if (
        rendered_messages
        and rendered_messages[-1].get("role") == "assistant"
        and "tool_calls" not in rendered_messages[-1]
    ):
        last_message = dict(rendered_messages[-1])
        existing_content = last_message.get("content", "")
        if not isinstance(existing_content, str):
            raise InvalidModelOutputError("Assistant prefill requires string assistant content")
        last_message["content"] = existing_content + assistant_prefill
        rendered_messages[-1] = last_message
        return rendered_messages

    rendered_messages.append({"role": "assistant", "content": assistant_prefill})
    return rendered_messages


def _relabel_hf_chat_template_snapshot(
    snapshot: AgentStateSnapshot,
    *,
    backend_label: str,
) -> AgentStateSnapshot:
    return {
        "version": snapshot["version"],
        "backend": backend_label,
        "data": dict(snapshot["data"]),
    }


def _unwrap_hf_chat_template_snapshot(
    snapshot: AgentStateSnapshot,
    *,
    backend_label: str,
) -> AgentStateSnapshot:
    if snapshot["backend"] != backend_label:
        raise AgentStateVersionError(f"Unsupported agent snapshot backend: {snapshot['backend']}")
    return {
        "version": snapshot["version"],
        "backend": "hf_chat_template",
        "data": dict(snapshot["data"]),
    }


class HFChatTemplateAgent(AgentProtocol):
    def __init__(
        self,
        *,
        backend: HFGenerationBackendProtocol,
        profile: HFModelProfile,
        parser: HFResponseParser,
        request_builder: HFRequestBuilder | None = None,
        debug_sink: AgentDebugSink | None = None,
        debug_backend_label: str = "hf_chat_template",
    ) -> None:
        self._backend = backend
        self._profile = profile
        self._parser = parser
        self._request_builder = request_builder or _build_default_hf_request
        self._debug_sink = debug_sink
        self._debug_backend_label = debug_backend_label
        self._state = HFChatTemplateAgentState()

    def next_action(
        self,
        *,
        history: RuntimeHistory,
        tools: Sequence[AgentToolSpec],
    ) -> AgentDecision:
        request = self._build_request(history, tools)
        state = self._state

        turn_index = state.next_debug_turn_index
        provider_payload = self._debug_provider_payload(request, tools)
        self._record_debug_event(
            phase="request_built",
            turn_index=turn_index,
            history=history,
            request_payload=self._serialize_payload(request),
            provider_payload=provider_payload,
        )

        started_at = time.perf_counter()
        response = self._backend.generate(request)
        latency_ms = (time.perf_counter() - started_at) * 1000.0

        response_payload = self._serialize_payload(response)
        self._record_debug_event(
            phase="response_received",
            turn_index=turn_index,
            history=history,
            response_payload=response_payload,
            latency_ms=latency_ms,
            provider_payload=provider_payload,
        )

        try:
            decision = self._parse_response(response, state=state)
        except InvalidModelOutputError as err:
            self._record_debug_event(
                phase="parse_error",
                turn_index=turn_index,
                history=history,
                request_payload=self._serialize_payload(request),
                response_payload=response_payload,
                error=str(err),
                latency_ms=latency_ms,
                provider_payload=provider_payload,
            )
            raise

        self._record_debug_event(
            phase="decision_emitted",
            turn_index=turn_index,
            history=history,
            decision_payload=serialize_agent_decision(decision),
            latency_ms=latency_ms,
            provider_payload=provider_payload,
        )

        self._state = state.advance(decision)
        return decision

    def reset_state(self) -> None:
        self._state = HFChatTemplateAgentState()

    def snapshot_state(self) -> AgentStateSnapshot:
        return {
            "version": AGENT_STATE_VERSION,
            "backend": "hf_chat_template",
            "data": {
                "next_generated_call_index": self._state.next_generated_call_index,
                "next_debug_turn_index": self._state.next_debug_turn_index,
            },
        }

    def restore_state(self, snapshot: AgentStateSnapshot) -> None:
        if snapshot["version"] != AGENT_STATE_VERSION:
            raise AgentStateVersionError(
                f"Unsupported agent snapshot version: {snapshot['version']}"
            )
        if snapshot["backend"] != "hf_chat_template":
            raise AgentStateVersionError(
                f"Unsupported agent snapshot backend: {snapshot['backend']}"
            )
        self._state = HFChatTemplateAgentState.from_snapshot_data(snapshot["data"])

    def _build_request(
        self, history: RuntimeHistory, tools: Sequence[AgentToolSpec]
    ) -> HFGenerationRequest:
        return self._request_builder(
            history=history,
            tools=tools,
            profile=self._profile,
            backend=self._backend,
        )

    def _parse_response(
        self,
        response: HFGenerationResponse,
        *,
        state: HFChatTemplateAgentState,
    ) -> AgentDecision:
        fallback_call_id = f"call_{state.next_generated_call_index:06d}"
        if response.parsed_response is not None:
            return normalize_parsed_response(
                response.parsed_response,
                fallback_call_id=fallback_call_id,
            )
        return self._parser.parse(response, fallback_call_id=fallback_call_id)

    def _debug_provider_payload(
        self,
        request: HFGenerationRequest,
        tools: Sequence[AgentToolSpec],
    ) -> dict[str, Any]:
        return {
            "chat_template": request.chat_template,
            "generation_mode": {
                "add_generation_prompt": request.add_generation_prompt,
                "continue_final_message": request.continue_final_message,
            },
            "tool_names": [tool.name for tool in tools],
        }

    def _record_debug_event(
        self,
        *,
        phase: DebugPhase,
        turn_index: int,
        history: RuntimeHistory,
        request_payload: Mapping[str, Any] | None = None,
        response_payload: Mapping[str, Any] | None = None,
        decision_payload: Mapping[str, Any] | None = None,
        error: str | None = None,
        latency_ms: float | None = None,
        provider_payload: Mapping[str, Any] | None = None,
    ) -> None:
        if self._debug_sink is None:
            return
        self._debug_sink.record(
            AgentDebugEvent(
                backend=self._debug_backend_label,
                model=self._backend.config.model_source(),
                phase=phase,
                turn_index=turn_index,
                history_summary=summarize_runtime_history(history),
                request_payload=request_payload,
                response_payload=response_payload,
                decision_payload=decision_payload,
                error=error,
                latency_ms=latency_ms,
                provider_payload=provider_payload or {},
            )
        )

    def _serialize_payload(self, payload: Any) -> dict[str, Any]:
        serialized = make_json_safe(payload)
        if isinstance(serialized, dict):
            return serialized
        return {"value": serialized}
