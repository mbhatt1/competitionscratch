"""JSONL writer for structured evaluator framework events."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any, TextIO

if TYPE_CHECKING:
    from .diagnostics import FrameworkEvent


class EventLogSink:
    """Write structured framework events as JSONL to an open text stream."""

    def __init__(self, handle: TextIO) -> None:
        self._handle = handle

    def record_event(self, event: FrameworkEvent) -> None:
        payload = {
            "at_utc": event.at_utc.isoformat(),
            "run_id": event.run_id,
            "phase": event.phase,
            "level": event.level,
            "kind": event.kind,
            "event": event.event,
            "message": event.message,
            "fields": _json_safe_mapping(event.fields),
        }
        self._handle.write(json.dumps(payload, sort_keys=True))
        self._handle.write("\n")
        self._handle.flush()

    def close(self) -> None:
        self._handle.close()


def open_event_log_sink(path: Path) -> EventLogSink:
    """Open a JSONL sink for ``path`` and create parent directories if needed.

    The caller owns the returned sink and must close it after logging finishes.
    """

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    handle = target.open("w", encoding="utf-8")
    return EventLogSink(handle)


def _json_safe_mapping(fields: Mapping[str, object]) -> dict[str, Any]:
    return {str(key): _json_safe(value) for key, value in fields.items()}


def _json_safe(value: object) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_json_safe(item) for item in value]
    if isinstance(value, set):
        return [_json_safe(item) for item in sorted(value, key=repr)]
    return repr(value)
