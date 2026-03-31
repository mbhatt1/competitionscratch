from __future__ import annotations

import copy
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Final
from weakref import WeakKeyDictionary

from aicomp_sdk.core.env.api import (
    EnvInteractionResult,
    _HarnessAttackEnvProtocol,
)

_GUARDRAIL_DENY_PREFIX: Final[str] = "denied:"
_GUARDRAIL_CONFIRM_PREFIX: Final[str] = "confirm_required:"
_OPAQUE_ATTACK_ENV_DIR: Final[tuple[str, ...]] = (
    "export_trace_dict",
    "interact",
    "reset",
    "restore",
    "seed",
    "snapshot",
)


def _redact_guardrail_error(error: str | None) -> str | None:
    """Normalize guardrail block reasons for attacker-visible traces."""
    if error is None:
        return None
    if error.startswith(_GUARDRAIL_DENY_PREFIX):
        return _GUARDRAIL_DENY_PREFIX[:-1]
    if error.startswith(_GUARDRAIL_CONFIRM_PREFIX):
        return _GUARDRAIL_CONFIRM_PREFIX[:-1]
    return error


def _project_attack_observation(observation: Any) -> Any:
    if not isinstance(observation, Mapping):
        return observation
    trace_summary_json = observation.get("trace_summary_json")
    if not isinstance(trace_summary_json, str):
        return observation
    try:
        summary = json.loads(trace_summary_json)
    except json.JSONDecodeError:
        return observation
    if not isinstance(summary, dict):
        return observation
    recent_errors = summary.get("recent_errors")
    if not isinstance(recent_errors, list):
        return observation
    projected_summary = dict(summary)
    projected_summary["recent_errors"] = [
        _redact_guardrail_error(error) if isinstance(error, str) else error
        for error in recent_errors
    ]
    projected_observation = dict(observation)
    projected_observation["trace_summary_json"] = json.dumps(
        projected_summary,
        sort_keys=True,
        separators=(",", ":"),
    )
    return projected_observation


def _project_attack_reset_result(result: Any) -> Any:
    if not isinstance(result, tuple) or len(result) != 2:
        return result
    observation, info = result
    if not isinstance(info, Mapping):
        return (_project_attack_observation(observation), info)
    projected_info = dict(info)
    trace = projected_info.get("trace")
    if isinstance(trace, Mapping):
        projected_info["trace"] = _project_attack_trace_dict(trace)
    return (_project_attack_observation(observation), projected_info)


def _project_attack_trace_dict(trace: Mapping[str, Any]) -> dict[str, Any]:
    """Project a raw trace dict into the attacker-visible trace shape."""
    projected = copy.deepcopy(dict(trace))
    tool_events = projected.get("tool_events")
    if not isinstance(tool_events, list):
        return projected
    for event in tool_events:
        if not isinstance(event, dict):
            continue
        error = event.get("error")
        if error is not None and not isinstance(error, str):
            continue
        event["error"] = _redact_guardrail_error(error)
    return projected


class _OpaqueEnvSnapshot:
    """Opaque snapshot token for attacker-visible evaluator environments."""

    __slots__ = ("__weakref__",)


@dataclass(slots=True)
class _OpaqueAttackEnvState:
    """Mutable backing state stored outside the attacker-visible wrapper."""

    inner: _HarnessAttackEnvProtocol
    snapshots: WeakKeyDictionary[_OpaqueEnvSnapshot, Any] = field(default_factory=WeakKeyDictionary)


def _build_opaque_attack_env_type() -> type:
    states: WeakKeyDictionary[object, _OpaqueAttackEnvState] = WeakKeyDictionary()

    class _OpaqueAttackEnv:
        """Attacker-facing proxy that hides harness internals and redacts traces.

        This is a tamper-resistant soft barrier, not a hard sandbox.
        """

        __slots__ = ("__weakref__",)

        def __init__(self, inner: _HarnessAttackEnvProtocol) -> None:
            states[self] = _OpaqueAttackEnvState(inner=inner)

        @property
        def seed(self) -> int:
            return states[self].inner.seed

        @seed.setter
        def seed(self, value: int) -> None:
            states[self].inner.seed = int(value)

        def reset(self, *args: Any, **kwargs: Any) -> Any:
            return _project_attack_reset_result(states[self].inner.reset(*args, **kwargs))

        def interact(
            self, user_message: str, max_tool_hops: int | None = None
        ) -> EnvInteractionResult:
            return states[self].inner.interact(user_message, max_tool_hops=max_tool_hops)

        def export_trace_dict(self) -> dict[str, Any]:
            return _project_attack_trace_dict(states[self].inner.export_trace_dict())

        def snapshot(self) -> _OpaqueEnvSnapshot:
            state = states[self]
            snapshot = _OpaqueEnvSnapshot()
            state.snapshots[snapshot] = state.inner.snapshot()
            return snapshot

        def restore(self, snapshot: Any) -> None:
            if not isinstance(snapshot, _OpaqueEnvSnapshot):
                raise TypeError("OpaqueAttackEnv.restore requires an OpaqueEnvSnapshot")
            state = states[self]
            try:
                inner_snapshot = state.snapshots[snapshot]
            except KeyError as err:
                raise ValueError("Unknown opaque snapshot token") from err
            state.inner.restore(inner_snapshot)

        def __dir__(self) -> list[str]:
            return list(_OPAQUE_ATTACK_ENV_DIR)

        def __repr__(self) -> str:
            return "OpaqueAttackEnv()"

    return _OpaqueAttackEnv


_OpaqueAttackEnv = _build_opaque_attack_env_type()
