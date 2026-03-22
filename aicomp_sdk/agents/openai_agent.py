"""
OpenAI Responses API agent.
"""

from __future__ import annotations

import copy
import json
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol, Self, Unpack

from aicomp_sdk.agents.debug import (
    AgentDebugEvent,
    AgentDebugSink,
    DebugPhase,
    serialize_agent_decision,
    summarize_runtime_history,
)
from aicomp_sdk.agents.protocol import AgentProtocol
from aicomp_sdk.agents.tool_specs import (
    build_openai_tool_name_maps,
    to_openai_function_tool,
)
from aicomp_sdk.agents.types import (
    AGENT_STATE_VERSION,
    AgentDecision,
    AgentStateSnapshot,
    AgentStateVersionError,
    AgentToolSpec,
    AssistantMessageEvent,
    FinalResponseDecision,
    InvalidModelOutputError,
    ToolCall,
    ToolCallDecision,
    ToolRequestEvent,
    ToolResultEvent,
    UserMessageEvent,
)
from aicomp_sdk.core.runtime_history import RuntimeHistory

if TYPE_CHECKING:
    from openai.types.responses import (
        Response,
        ResponseFunctionToolCall,
        ResponseOutputItem,
    )
    from openai.types.responses.response_create_params import ResponseCreateParamsNonStreaming


class ResponsesAPIProtocol(Protocol):
    def create(self, **kwargs: Unpack[ResponseCreateParamsNonStreaming]) -> Response:
        """Create a non-streaming Responses API request."""


class OpenAIClientProtocol(Protocol):
    @property
    def responses(self) -> ResponsesAPIProtocol:
        """Access the Responses API resource."""


@dataclass(frozen=True)
class OpenAIResponsesAgentState:
    next_debug_turn_index: int = 1
    pending_response_output_items: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.next_debug_turn_index < 1:
            raise ValueError("next_debug_turn_index must be >= 1")
        normalized_items: list[dict[str, Any]] = []
        for index, item in enumerate(self.pending_response_output_items):
            if not isinstance(item, Mapping):
                raise ValueError(f"pending_response_output_items[{index}] must be an object")
            normalized_item = dict(item)
            if not all(isinstance(key, str) for key in normalized_item):
                raise ValueError(f"pending_response_output_items[{index}] keys must be strings")
            normalized_items.append(copy.deepcopy(normalized_item))
        object.__setattr__(self, "pending_response_output_items", normalized_items)

    def advance(
        self,
        decision: AgentDecision,
        output_items: Sequence[ResponseOutputItem],
    ) -> Self:
        pending_response_output_items: list[dict[str, Any]] = []
        if isinstance(decision, ToolCallDecision):
            pending_response_output_items = [
                item.model_dump(mode="json", exclude_unset=True) for item in output_items
            ]
        return type(self)(
            next_debug_turn_index=self.next_debug_turn_index + 1,
            pending_response_output_items=pending_response_output_items,
        )

    def cleared_pending_response_output_items(self) -> Self:
        if not self.pending_response_output_items:
            return self
        return type(self)(
            next_debug_turn_index=self.next_debug_turn_index,
        )

    @classmethod
    def from_snapshot_data(cls, data: object) -> Self:
        if not isinstance(data, Mapping):
            raise AgentStateVersionError("Invalid agent snapshot data: expected object")
        try:
            return cls(
                next_debug_turn_index=cls._require_positive_int(
                    data,
                    key="next_debug_turn_index",
                ),
                pending_response_output_items=cls._require_pending_output_items(data),
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

    @staticmethod
    def _require_pending_output_items(
        data: Mapping[str, object],
    ) -> list[dict[str, Any]]:
        if "pending_response_output_items" not in data:
            raise ValueError("missing pending_response_output_items")
        raw_value = data["pending_response_output_items"]
        if not isinstance(raw_value, list):
            raise ValueError("pending_response_output_items must be a list")
        normalized_items: list[dict[str, Any]] = []
        for index, item in enumerate(raw_value):
            if not isinstance(item, Mapping):
                raise ValueError(f"pending_response_output_items[{index}] must be an object")
            normalized_item = dict(item)
            if not all(isinstance(key, str) for key in normalized_item):
                raise ValueError(f"pending_response_output_items[{index}] keys must be strings")
            normalized_items.append(normalized_item)
        return normalized_items


class OpenAIResponsesAgent(AgentProtocol):
    """OpenAI Responses-backed tool-using agent."""

    def __init__(
        self,
        *,
        client: OpenAIClientProtocol,
        verbose: bool = False,
        model: str = "gpt-4o-mini",
        debug_sink: AgentDebugSink | None = None,
    ) -> None:
        self._client = client
        self.verbose = verbose
        self._model = model
        self._debug_sink = debug_sink
        self._state = OpenAIResponsesAgentState()

    def next_action(
        self,
        *,
        history: RuntimeHistory,
        tools: Sequence[AgentToolSpec],
    ) -> AgentDecision:
        state = self._effective_state_for_history(history)
        canonical_to_openai, openai_to_canonical = build_openai_tool_name_maps(tools)
        provider_payload = self._debug_provider_payload(
            history,
            tools,
            canonical_to_openai,
            state=state,
        )
        request = self._build_request(history, tools, canonical_to_openai, state=state)
        turn_index = state.next_debug_turn_index
        self._record_debug_event(
            phase="request_built",
            turn_index=turn_index,
            history=history,
            request_payload=request,
            provider_payload=provider_payload,
        )
        started_at = time.perf_counter()
        response = self._client.responses.create(**request)
        latency_ms = (time.perf_counter() - started_at) * 1000.0
        response_payload = response.model_dump(mode="json", exclude_unset=True)
        self._record_debug_event(
            phase="response_received",
            turn_index=turn_index,
            history=history,
            response_payload=response_payload,
            latency_ms=latency_ms,
            provider_payload=provider_payload,
        )
        try:
            self._raise_for_response_error(response)
            decision = self._parse_response(response, openai_to_canonical)
        except InvalidModelOutputError as err:
            self._record_debug_event(
                phase="parse_error",
                turn_index=turn_index,
                history=history,
                request_payload=request,
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
        self._state = state.advance(decision, response.output)
        return decision

    def reset_state(self) -> None:
        self._state = OpenAIResponsesAgentState()

    def snapshot_state(self) -> AgentStateSnapshot:
        return {
            "version": AGENT_STATE_VERSION,
            "backend": "openai_responses",
            "data": {
                "pending_response_output_items": copy.deepcopy(
                    self._state.pending_response_output_items
                ),
                "next_debug_turn_index": self._state.next_debug_turn_index,
            },
        }

    def restore_state(self, snapshot: AgentStateSnapshot) -> None:
        if snapshot["version"] != AGENT_STATE_VERSION:
            raise AgentStateVersionError(
                f"Unsupported agent snapshot version: {snapshot['version']}"
            )
        if snapshot["backend"] != "openai_responses":
            raise AgentStateVersionError(
                f"Unsupported agent snapshot backend: {snapshot['backend']}"
            )
        self._state = OpenAIResponsesAgentState.from_snapshot_data(snapshot["data"])

    def _build_request(
        self,
        history: RuntimeHistory,
        tools: Sequence[AgentToolSpec],
        canonical_to_openai: Mapping[str, str],
        *,
        state: OpenAIResponsesAgentState,
    ) -> ResponseCreateParamsNonStreaming:
        request: ResponseCreateParamsNonStreaming = {
            "model": self._model,
            "input": self._render_input_items(
                history,
                canonical_to_openai,
                state=state,
            ),
            "tools": [
                to_openai_function_tool(
                    spec,
                    name_override=canonical_to_openai.get(spec.name, spec.name),
                )
                for spec in tools
            ],
            "parallel_tool_calls": False,
            "temperature": 0,
        }

        instructions = self._render_instructions(history)
        if instructions is not None:
            request["instructions"] = instructions

        return request

    def _raise_for_response_error(self, response: Response) -> None:
        if response.error is not None:
            raise InvalidModelOutputError(f"OpenAI response error: {response.error}")
        if response.incomplete_details is not None:
            raise InvalidModelOutputError(
                f"OpenAI response incomplete: {response.incomplete_details}"
            )

    def _render_input_items(
        self,
        history: RuntimeHistory,
        canonical_to_openai: Mapping[str, str],
        *,
        state: OpenAIResponsesAgentState,
    ) -> list[dict[str, Any]]:
        """
        Render Responses API input from canonical runtime history.

        If the previous OpenAI turn ended in a tool request, and the current history ends
        with the matching tool request/result suffix, resume that provider-private turn by
        sending:
        1. the base history before the trailing roundtrip,
        2. the stored output items from the prior response,
        3. the new function_call_output for the trailing tool result.

        Otherwise, render the full canonical history directly.
        """
        split_roundtrip = history.split_trailing_tool_roundtrip()
        if state.pending_response_output_items and split_roundtrip is not None:
            base_history, _request_event, result_event = split_roundtrip
            items = self._render_history_items(base_history, canonical_to_openai)
            items.extend(copy.deepcopy(state.pending_response_output_items))
            items.append(
                {
                    "type": "function_call_output",
                    "call_id": result_event.result.call_id,
                    "output": result_event.result.output_text,
                }
            )
            return items
        return self._render_history_items(history, canonical_to_openai)

    def _render_history_items(
        self,
        history: RuntimeHistory,
        canonical_to_openai: Mapping[str, str],
    ) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for event in history.events:
            if isinstance(event, UserMessageEvent):
                items.append(
                    {
                        "type": "message",
                        "role": "user",
                        "content": [{"type": "input_text", "text": event.text}],
                    }
                )
                continue
            if isinstance(event, AssistantMessageEvent):
                items.append(
                    {
                        "type": "message",
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": event.text}],
                    }
                )
                continue
            if isinstance(event, ToolRequestEvent):
                items.append(
                    {
                        "type": "function_call",
                        "call_id": event.call.call_id,
                        "name": canonical_to_openai.get(
                            event.call.tool_name,
                            event.call.tool_name,
                        ),
                        "arguments": json.dumps(event.call.arguments, sort_keys=True),
                    }
                )
                continue
            if isinstance(event, ToolResultEvent):
                items.append(
                    {
                        "type": "function_call_output",
                        "call_id": event.result.call_id,
                        "output": event.result.output_text,
                    }
                )
                continue
            raise InvalidModelOutputError(f"Unsupported runtime event: {event!r}")
        return items

    def _render_instructions(self, history: RuntimeHistory) -> str | None:
        if not history.instructions:
            return None
        return "\n\n".join(event.text for event in history.instructions if event.text.strip())

    def _parse_response(
        self,
        response: Response,
        openai_to_canonical: Mapping[str, str],
    ) -> AgentDecision:
        assistant_text_chunks: list[str] = []
        function_tool_call: ResponseFunctionToolCall | None = None

        for output in response.output:
            if output.type == "function_call":
                if function_tool_call is not None:
                    raise InvalidModelOutputError("OpenAI response returned multiple tool calls")
                function_tool_call = output
                continue

            if output.type != "message":
                continue

            for content in output.content:
                if content.type != "output_text":
                    continue

                text = content.text
                if text.strip():
                    assistant_text_chunks.append(text)

        if not assistant_text_chunks and response.output_text.strip():
            assistant_text_chunks.append(response.output_text.strip())

        assistant_text = "\n".join(
            chunk.strip() for chunk in assistant_text_chunks if chunk.strip()
        )

        if function_tool_call is not None:
            raw_arguments = function_tool_call.arguments
            raw_tool_name = function_tool_call.name
            try:
                arguments = json.loads(raw_arguments)
            except Exception as err:
                raise InvalidModelOutputError("Function call arguments are not valid JSON") from err

            if not isinstance(arguments, dict):
                raise InvalidModelOutputError("Function call arguments must decode to an object")

            return ToolCallDecision(
                call=ToolCall(
                    call_id=function_tool_call.call_id,
                    tool_name=openai_to_canonical.get(raw_tool_name, raw_tool_name),
                    arguments=arguments,
                ),
                assistant_message=assistant_text or None,
            )

        if assistant_text:
            return FinalResponseDecision(text=assistant_text)

        raise InvalidModelOutputError(
            "OpenAI response produced neither assistant text nor tool call"
        )

    def _debug_provider_payload(
        self,
        history: RuntimeHistory,
        tools: Sequence[AgentToolSpec],
        canonical_to_openai: Mapping[str, str],
        *,
        state: OpenAIResponsesAgentState,
    ) -> dict[str, Any]:
        split_roundtrip = history.split_trailing_tool_roundtrip()
        used_pending_turn_output = bool(
            state.pending_response_output_items and split_roundtrip is not None
        )
        return {
            "used_pending_turn_output": used_pending_turn_output,
            "pending_turn_output_item_count": len(state.pending_response_output_items),
            "tool_names": [tool.name for tool in tools],
            "registered_tool_names": [
                canonical_to_openai.get(tool.name, tool.name) for tool in tools
            ],
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
                backend="openai_responses",
                model=self._model,
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

    def _effective_state_for_history(
        self,
        history: RuntimeHistory,
    ) -> OpenAIResponsesAgentState:
        if (
            self._state.pending_response_output_items
            and history.split_trailing_tool_roundtrip() is None
        ):
            return self._state.cleared_pending_response_output_items()
        return self._state
