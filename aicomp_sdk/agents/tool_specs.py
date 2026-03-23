from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any, Final

from aicomp_sdk.agents.types import AgentToolSpec, JsonObject

if TYPE_CHECKING:
    from aicomp_sdk.core.tools import RuntimeToolSpec


_OPENAI_TOOL_NAME_SAFE_CHARS_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9_-]+")
_OPENAI_TOOL_NAME_MAX_LEN: Final[int] = 64


def serialize_tool_output(value: Any) -> str:
    """Convert a tool result into deterministic text for model consumption."""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def to_openai_function_tool(
    spec: AgentToolSpec,
    *,
    name_override: str | None = None,
) -> JsonObject:
    return {
        "type": "function",
        "name": name_override or spec.name,
        "description": spec.description,
        "parameters": _to_openai_parameters_schema(spec.parameters_json_schema, strict=spec.strict),
        "strict": spec.strict,
    }


def to_hf_function_tool(spec: AgentToolSpec) -> JsonObject:
    return {
        "type": "function",
        "function": {
            "name": spec.name,
            "description": spec.description,
            "parameters": spec.parameters_json_schema,
        },
    }


def to_agent_tool_spec(tool: RuntimeToolSpec) -> AgentToolSpec:
    """Project canonical runtime metadata into the agent-facing registration view.

    This preserves the semantic meaning of the canonical runtime schema instead
    of introducing backend-specific schema divergence at the projection step.
    """

    return AgentToolSpec(
        name=tool.name,
        description=tool.description,
        parameters_json_schema=dict(tool.parameters_json_schema),
        strict=True,
    )


def to_agent_tool_specs(
    tools: Sequence[RuntimeToolSpec],
) -> tuple[AgentToolSpec, ...]:
    return tuple(to_agent_tool_spec(tool) for tool in tools)


def build_openai_tool_name_maps(
    tools: Sequence[AgentToolSpec],
) -> tuple[dict[str, str], dict[str, str]]:
    canonical_to_openai: dict[str, str] = {}
    openai_to_canonical: dict[str, str] = {}

    for spec in tools:
        alias = _sanitize_openai_tool_name(spec.name)
        if alias in openai_to_canonical and openai_to_canonical[alias] != spec.name:
            alias = _with_hash_suffix(alias, spec.name)
        while alias in openai_to_canonical and openai_to_canonical[alias] != spec.name:
            alias = _with_hash_suffix(alias, spec.name + alias)
        canonical_to_openai[spec.name] = alias
        openai_to_canonical[alias] = spec.name

    return canonical_to_openai, openai_to_canonical


def _sanitize_openai_tool_name(name: str) -> str:
    sanitized = _OPENAI_TOOL_NAME_SAFE_CHARS_RE.sub("_", name).strip("_")
    if not sanitized:
        sanitized = "tool"
    if len(sanitized) <= _OPENAI_TOOL_NAME_MAX_LEN:
        return sanitized
    return _with_hash_suffix(sanitized, name)


def _with_hash_suffix(base_name: str, raw_name: str) -> str:
    digest = hashlib.sha1(raw_name.encode("utf-8"), usedforsecurity=False).hexdigest()[:8]
    max_base_length = _OPENAI_TOOL_NAME_MAX_LEN - len(digest) - 1
    trimmed = base_name[:max_base_length].rstrip("_-")
    if not trimmed:
        trimmed = "tool"
    return f"{trimmed}_{digest}"


def _to_openai_parameters_schema(schema: JsonObject, *, strict: bool) -> JsonObject:
    copied_schema = copy.deepcopy(dict(schema))
    if not strict:
        return copied_schema
    if copied_schema.get("type") != "object":
        return copied_schema

    properties = copied_schema.get("properties")
    if not isinstance(properties, dict):
        return copied_schema

    required_value = copied_schema.get("required", [])
    required_names: set[str] = set()
    if isinstance(required_value, Sequence) and not isinstance(required_value, (str, bytes)):
        required_names = {name for name in required_value if isinstance(name, str)}
    openai_properties: dict[str, Any] = {}
    for name, property_schema in properties.items():
        if not isinstance(property_schema, dict):
            openai_properties[name] = copy.deepcopy(property_schema)
            continue
        if name in required_names:
            openai_properties[name] = copy.deepcopy(property_schema)
            continue
        openai_properties[name] = _make_property_nullable(property_schema)

    copied_schema["properties"] = openai_properties
    copied_schema["required"] = list(openai_properties.keys())
    return copied_schema


def _make_property_nullable(schema: dict[str, Any]) -> dict[str, Any]:
    copied_schema = copy.deepcopy(schema)
    if _schema_allows_null(copied_schema):
        return copied_schema
    return {
        "anyOf": [copied_schema, {"type": "null"}],
        **({"description": copied_schema["description"]} if "description" in copied_schema else {}),
    }


def _schema_allows_null(schema: dict[str, Any]) -> bool:
    schema_type = schema.get("type")
    if schema_type == "null":
        return True
    if isinstance(schema_type, list) and "null" in schema_type:
        return True
    any_of = schema.get("anyOf")
    if isinstance(any_of, list):
        return any(isinstance(option, dict) and option.get("type") == "null" for option in any_of)
    return False
