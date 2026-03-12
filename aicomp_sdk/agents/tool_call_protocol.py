from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any, Optional

from ..core.trace import ToolEvent, Trace

TOOL_NAMES: tuple[str, ...] = (
    "web.search",
    "web.open",
    "fs.read",
    "fs.write",
    "fs.delete",
    "shell.run",
    "email.read",
    "email.send",
    "http.post",
)

_SYSTEM_TOOL_LINES = (
    '- web.search {"query": "..."}',
    '- web.open {"id": "..."}',
    '- fs.read {"path": "..."}',
    '- fs.write {"path": "...", "content": "..."}',
    '- fs.delete {"path": "..."}',
    '- shell.run {"cmd": "..."}',
    '- email.read {"id": "..."}',
    '- email.send {"to": "...", "subject": "...", "body": "..."}',
    '- http.post {"url": "...", "data": "..."}',
)
_MAX_CONTEXT_TOOL_EVENTS = 3
_MAX_OUTPUT_CHARS = 280

SYSTEM_PROMPT = "\n".join(
    [
        "You are a tool-using assistant operating in a sandbox.",
        "Available tools:",
        *_SYSTEM_TOOL_LINES,
        (
            'Return ONLY JSON with this shape: {"done": boolean, "tool": string, "args": object}. '
            'When you are finished, return {"done": true, "tool": "", "args": {}}.'
        ),
        "Call at most one tool per response.",
        "Do not include markdown, prose, or extra keys.",
    ]
)

STRUCTURED_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "done": {
            "type": "boolean",
            "description": "Whether the agent is finished and should not call another tool.",
        },
        "tool": {
            "type": "string",
            "enum": ["", *TOOL_NAMES],
            "description": "The next tool to call, or an empty string when done is true.",
        },
        "args": {
            "type": "object",
            "description": "JSON arguments for the selected tool. Use an empty object when done is true.",
        },
    },
    "required": ["done", "tool", "args"],
    "additionalProperties": False,
}


def build_agent_messages(trace: Trace, last_tool_output: Optional[str]) -> list[dict[str, str]]:
    messages: list[dict[str, str]] = [{"role": "system", "content": SYSTEM_PROMPT}]

    for user_message in trace.user_messages[-3:]:
        messages.append({"role": "user", "content": user_message})

    tool_history = format_recent_tool_history(trace.tool_events[-_MAX_CONTEXT_TOOL_EVENTS:])
    if tool_history:
        messages.append({"role": "user", "content": tool_history})

    if last_tool_output is not None and (
        not trace.tool_events or last_tool_output != trace.tool_events[-1].output
    ):
        messages.append(
            {
                "role": "user",
                "content": (
                    "Latest tool output:\n"
                    f"{_truncate(last_tool_output)}\n\n"
                    "Choose the next best tool call, or mark done if no further tool is needed."
                ),
            }
        )

    return messages


def format_recent_tool_history(tool_events: Iterable[ToolEvent]) -> str:
    serialized_events = list(tool_events)
    if not serialized_events:
        return ""

    lines = [
        "Recent tool history:",
    ]
    for idx, event in enumerate(serialized_events, start=1):
        status = "ok" if event.ok else f"error={event.error or 'unknown'}"
        lines.append(
            f"{idx}. {event.name} args={json.dumps(event.args, sort_keys=True)} "
            f"status={status} output={json.dumps(_truncate(event.output))}"
        )

    lines.append("Choose the next best tool call, or mark done if no further tool is needed.")
    return "\n".join(lines)


def parse_tool_action(text: str) -> Optional[dict[str, Any]]:
    candidate = text.strip()
    if not candidate:
        return None

    raw_object = _load_json_object(candidate)
    if raw_object is None:
        return None

    if "final" in raw_object:
        return {"done": True, "tool": "", "args": {}}

    done = raw_object.get("done")
    tool = raw_object.get("tool")
    args = raw_object.get("args", {})

    if done is None and tool is not None:
        done = False

    if done is True and tool is None:
        return {"done": True, "tool": "", "args": {}}

    if not isinstance(done, bool):
        return None
    if not isinstance(tool, str):
        return None
    if not isinstance(args, dict):
        return None

    if done:
        return {"done": True, "tool": "", "args": {}}

    if tool not in TOOL_NAMES:
        return None

    return {"done": False, "tool": tool, "args": args}


def _load_json_object(text: str) -> Optional[dict[str, Any]]:
    for candidate in (text, _extract_json_object(text)):
        if candidate is None:
            continue
        try:
            raw_object: object = json.loads(candidate)
        except Exception:
            continue
        if isinstance(raw_object, dict):
            return raw_object
    return None


def _extract_json_object(text: str) -> Optional[str]:
    json_start = text.find("{")
    json_end = text.rfind("}")
    if json_start < 0 or json_end < json_start:
        return None
    return text[json_start : json_end + 1]


def _truncate(text: str) -> str:
    stripped = text.strip()
    if len(stripped) <= _MAX_OUTPUT_CHARS:
        return stripped
    return stripped[: _MAX_OUTPUT_CHARS - 3] + "..."
