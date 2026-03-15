from __future__ import annotations

from aicomp_sdk.agents.tool_specs import (
    build_openai_tool_name_maps,
    to_openai_function_tool,
)
from aicomp_sdk.agents.types import AgentToolSpec


def test_build_openai_tool_name_maps_sanitizes_dotted_tool_names() -> None:
    specs = [
        AgentToolSpec(
            name="fs.read",
            description="Read a file.",
            parameters_json_schema={"type": "object"},
        ),
        AgentToolSpec(
            name="http.post",
            description="Post data.",
            parameters_json_schema={"type": "object"},
        ),
    ]

    canonical_to_openai, openai_to_canonical = build_openai_tool_name_maps(specs)

    assert canonical_to_openai == {
        "fs.read": "fs_read",
        "http.post": "http_post",
    }
    assert openai_to_canonical == {
        "fs_read": "fs.read",
        "http_post": "http.post",
    }


def test_to_openai_function_tool_supports_name_override() -> None:
    spec = AgentToolSpec(
        name="fs.read",
        description="Read a file.",
        parameters_json_schema={"type": "object"},
    )

    rendered = to_openai_function_tool(spec, name_override="fs_read")

    assert rendered == {
        "type": "function",
        "name": "fs_read",
        "description": "Read a file.",
        "parameters": {"type": "object"},
        "strict": True,
    }


def test_to_openai_function_tool_makes_optional_properties_nullable_under_strict() -> None:
    spec = AgentToolSpec(
        name="email.list",
        description="List email summaries.",
        parameters_json_schema={
            "type": "object",
            "properties": {
                "folder": {"type": "string", "description": "Folder name."},
                "limit": {"type": "integer", "description": "Page size."},
                "cursor": {
                    "anyOf": [{"type": "string"}, {"type": "null"}],
                    "description": "Pagination cursor.",
                },
            },
            "required": ["folder"],
            "additionalProperties": False,
        },
    )

    rendered = to_openai_function_tool(spec, name_override="email_list")

    assert rendered["strict"] is True
    parameters = rendered["parameters"]
    assert parameters["required"] == ["folder", "limit", "cursor"]
    assert parameters["properties"]["folder"] == {
        "type": "string",
        "description": "Folder name.",
    }
    assert parameters["properties"]["limit"] == {
        "anyOf": [
            {"type": "integer", "description": "Page size."},
            {"type": "null"},
        ],
        "description": "Page size.",
    }
    assert parameters["properties"]["cursor"] == {
        "anyOf": [{"type": "string"}, {"type": "null"}],
        "description": "Pagination cursor.",
    }
