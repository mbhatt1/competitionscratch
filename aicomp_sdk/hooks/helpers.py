"""Generic hook callback factory helpers."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from aicomp_sdk.hooks.types import HookCallback, HookContext, HookResult


def create_payload_injection_hook(
    payload_generator: Callable[[HookContext], str | None],
) -> HookCallback:
    """Create a callback that appends payload text to context or tool output."""

    def hook(context: HookContext) -> HookResult:
        payload = payload_generator(context)
        if payload:
            context.injected_content = payload
            return HookResult(
                continue_execution=True,
                metadata={"payload_injected": True},
            )
        return HookResult(continue_execution=True)

    return hook


def create_trigger_hook(
    trigger_condition: Callable[[HookContext], bool],
    on_trigger: Callable[[HookContext], HookContext],
) -> HookCallback:
    """Create a callback that replaces the current context when a predicate matches."""

    def hook(context: HookContext) -> HookResult:
        if trigger_condition(context):
            return HookResult(
                continue_execution=True,
                modified_context=on_trigger(context),
                metadata={"trigger_matched": True},
            )
        return HookResult(continue_execution=True)

    return hook


def create_detection_hook(detector: Callable[[HookContext], bool]) -> HookCallback:
    """Create a callback that reports whether a detector matched."""

    def hook(context: HookContext) -> HookResult:
        detected = detector(context)
        return HookResult(
            continue_execution=True,
            payload_detected=detected,
            metadata={"detection_result": detected},
        )

    return hook


def create_memory_hook(
    memory_key: str,
    extractor: Callable[[HookContext], Any],
) -> HookCallback:
    """Create a callback that stores one extracted value in `hook_state`."""

    def hook(context: HookContext) -> HookResult:
        context.hook_state[memory_key] = extractor(context)
        return HookResult(
            continue_execution=True,
            metadata={"stored_to_memory": memory_key},
        )

    return hook
