"""Env-local hook registry and mutable hook runtime state."""

from __future__ import annotations

import copy
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Final, TypedDict

from aicomp_sdk.hooks.types import HookCallback, HookContext, HookResult, HookStage

_PAYLOAD_STORAGE_KEY: Final[str] = "_payload_storage"


class _HookEntry(TypedDict):
    callback: HookCallback
    priority: int


@dataclass(frozen=True, slots=True)
class _ToolEventSnapshot:
    name: str
    args: Mapping[str, Any]
    ok: bool
    output: str
    side_effect: str
    scope: str
    source: str
    error: str | None


@dataclass(frozen=True, slots=True)
class _TraceSnapshot:
    seed: Any
    user_messages: tuple[str, ...]
    tool_events: tuple[_ToolEventSnapshot, ...]
    assistant_messages: tuple[str, ...]


def _new_hook_state() -> dict[str, Any]:
    return {_PAYLOAD_STORAGE_KEY: []}


def _coerce_hook_state(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    hook_state = copy.deepcopy(dict(snapshot))
    if not isinstance(hook_state.get(_PAYLOAD_STORAGE_KEY), list):
        hook_state[_PAYLOAD_STORAGE_KEY] = []
    return hook_state


def _payload_storage(hook_state: dict[str, Any]) -> list[dict[str, Any]]:
    payloads = hook_state.get(_PAYLOAD_STORAGE_KEY)
    if not isinstance(payloads, list):
        payloads = []
        hook_state[_PAYLOAD_STORAGE_KEY] = payloads
    return payloads


def _freeze_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {item_key: _freeze_value(item_value) for item_key, item_value in value.items()}
        )
    if isinstance(value, list | tuple):
        return tuple(_freeze_value(item_value) for item_value in value)
    if isinstance(value, set | frozenset):
        return frozenset(_freeze_value(item_value) for item_value in value)
    return copy.deepcopy(value)


def _copy_trace_snapshot(trace: Any | None) -> Any | None:
    if trace is None:
        return None
    if not all(
        hasattr(trace, attr)
        for attr in ("seed", "user_messages", "tool_events", "assistant_messages")
    ):
        return copy.deepcopy(trace)
    return _TraceSnapshot(
        seed=copy.deepcopy(trace.seed),
        user_messages=tuple(trace.user_messages),
        tool_events=tuple(
            _ToolEventSnapshot(
                name=tool_event.name,
                args=_freeze_value(tool_event.args),
                ok=tool_event.ok,
                output=tool_event.output,
                side_effect=tool_event.side_effect,
                scope=tool_event.scope,
                source=tool_event.source,
                error=tool_event.error,
            )
            for tool_event in trace.tool_events
        ),
        assistant_messages=tuple(trace.assistant_messages),
    )


def _check_trigger(trigger: Mapping[str, Any], context: Mapping[str, Any]) -> bool:
    trigger_type = trigger.get("type")

    if trigger_type == "keyword":
        keywords = trigger.get("keywords", [])
        text = context.get("text", "").lower()
        return any(keyword.lower() in text for keyword in keywords)

    if trigger_type == "tool_sequence":
        required_sequence = trigger.get("sequence", [])
        recent_tools = context.get("recent_tools", [])
        if len(recent_tools) < len(required_sequence):
            return False
        return any(
            recent_tools[index : index + len(required_sequence)] == required_sequence
            for index in range(len(recent_tools) - len(required_sequence) + 1)
        )

    if trigger_type == "context_pattern":
        pattern = trigger.get("pattern", {})
        return all(context.get(key) == value for key, value in pattern.items())

    return False


def _retrieve_payloads(
    hook_state: dict[str, Any],
    trigger_context: Mapping[str, Any],
) -> list[dict[str, Any]]:
    return [
        stored_payload
        for stored_payload in _payload_storage(hook_state)
        if any(
            _check_trigger(trigger, trigger_context)
            for trigger in stored_payload["payload"].get("triggers", [])
        )
    ]


def _apply_modified_context(
    context: HookContext,
    modified_context: HookContext,
    *,
    hook_state: dict[str, Any],
    trace_snapshot: Any | None,
) -> None:
    context.stage = modified_context.stage
    context.tool_name = modified_context.tool_name
    context.tool_args = modified_context.tool_args
    context.tool_output = modified_context.tool_output
    context.guardrail_decision = modified_context.guardrail_decision
    context.context = modified_context.context
    context.metadata = modified_context.metadata
    context.modified_args = modified_context.modified_args
    context.modified_output = modified_context.modified_output
    context.injected_content = modified_context.injected_content
    context.should_block = modified_context.should_block
    context.hook_state = hook_state
    context.trace = trace_snapshot


class HookRegistry:
    """Env-local hook registry and mutable state bag."""

    def __init__(self) -> None:
        self._hooks: dict[HookStage, list[_HookEntry]] = {stage: [] for stage in HookStage}
        self._hook_state = _new_hook_state()

    def register_hook(
        self,
        stage: HookStage,
        callback: HookCallback,
        priority: int = 0,
    ) -> None:
        """Register a callback at one hook stage."""
        self._hooks[stage].append({"callback": callback, "priority": priority})
        self._hooks[stage].sort(key=lambda hook: hook["priority"], reverse=True)

    def unregister_hook(self, stage: HookStage, callback: HookCallback) -> None:
        """Remove a callback from one stage."""
        self._hooks[stage] = [hook for hook in self._hooks[stage] if hook["callback"] != callback]

    def execute_hooks(self, stage: HookStage, context: HookContext) -> list[HookResult]:
        """Execute all callbacks for one stage in descending priority order."""
        results: list[HookResult] = []
        trace_snapshot = _copy_trace_snapshot(context.trace)
        context.hook_state = self._hook_state
        context.trace = trace_snapshot
        for hook_data in self._hooks[stage]:
            try:
                result = hook_data["callback"](context)
                results.append(result)

                if result.modified_context:
                    _apply_modified_context(
                        context,
                        result.modified_context,
                        hook_state=self._hook_state,
                        trace_snapshot=trace_snapshot,
                    )
                if not result.continue_execution:
                    break
            except Exception as err:
                results.append(
                    HookResult(
                        continue_execution=True,
                        metadata={"error": str(err)},
                    )
                )
            finally:
                context.trace = trace_snapshot
        return results

    def store_payload(self, payload_id: str, payload: Mapping[str, Any]) -> None:
        """Store one payload record for retrieval by trigger-matching hooks."""
        _payload_storage(self._hook_state).append(
            {
                "id": payload_id,
                "payload": payload,
                "stored_at": None,
            }
        )

    def retrieve_payloads(self, trigger_context: Mapping[str, Any]) -> list[dict[str, Any]]:
        """Retrieve payloads whose trigger definitions match a context snapshot."""
        return _retrieve_payloads(self._hook_state, trigger_context)

    def get_persistent_state(self, key: str, default: Any = None) -> Any:
        """Read one env-local hook state value."""
        return self._hook_state.get(key, default)

    def set_persistent_state(self, key: str, value: Any) -> None:
        """Write one env-local hook state value."""
        self._hook_state[key] = value

    def snapshot_state(self) -> dict[str, Any]:
        """Capture mutable hook runtime state without callback registrations."""
        return copy.deepcopy(self._hook_state)

    def restore_state(self, snapshot: Mapping[str, Any]) -> None:
        """Restore mutable hook runtime state without changing registrations."""
        self._hook_state = _coerce_hook_state(snapshot)

    def clear_all(self) -> None:
        """Remove all callbacks and reset env-local hook state."""
        for stage in HookStage:
            self._hooks[stage] = []
        self._hook_state = _new_hook_state()
