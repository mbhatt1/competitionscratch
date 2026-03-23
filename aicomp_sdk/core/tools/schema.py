from __future__ import annotations

import inspect
from typing import Any, Final, get_type_hints

from pydantic import TypeAdapter

from .models import RuntimeToolSpec, ToolDef, ToolHandler
from .state import ToolContext

_GOOGLE_DOCSTRING_SECTION_HEADERS: Final[frozenset[str]] = frozenset(
    {"Args:", "Returns:", "Raises:", "Examples:"}
)
_MISSING_ARGS_SECTION_ERROR: Final[str] = (
    "Tool handlers with visible parameters must document them in a Google-style Args section"
)


def build_runtime_tool_spec(tool_def: ToolDef) -> RuntimeToolSpec:
    visible_parameters = _get_visible_parameters(tool_def.handler)
    docstring = inspect.getdoc(tool_def.handler) or ""
    description, argument_descriptions = _parse_google_docstring(
        docstring,
        tuple(parameter.name for parameter in visible_parameters),
    )
    type_hints = get_type_hints(tool_def.handler)
    properties: dict[str, dict[str, Any]] = {}
    required: list[str] = []

    for parameter in visible_parameters:
        annotation = type_hints.get(parameter.name, parameter.annotation)
        properties[parameter.name] = {
            **_schema_for_annotation(annotation),
            "description": argument_descriptions[parameter.name],
        }
        if parameter.default is inspect._empty:
            required.append(parameter.name)

    return RuntimeToolSpec(
        name=tool_def.name,
        description=description,
        side_effect=tool_def.side_effect,
        scope=tool_def.scope,
        parameters_json_schema={
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": False,
        },
    )


def _get_visible_parameters(handler: ToolHandler) -> tuple[inspect.Parameter, ...]:
    signature = inspect.signature(handler)
    type_hints = get_type_hints(handler)
    parameters = tuple(signature.parameters.values())

    if not parameters:
        raise TypeError("Tool handlers must declare ToolContext as the first parameter")

    context_parameter = parameters[0]
    context_annotation = type_hints.get(context_parameter.name, context_parameter.annotation)
    if context_annotation is not ToolContext:
        raise TypeError("Tool handlers must declare ToolContext as the first parameter")
    if context_parameter.kind is not inspect.Parameter.POSITIONAL_OR_KEYWORD:
        raise TypeError("Injected ToolContext parameter must be positional-or-keyword")

    visible_parameters: list[inspect.Parameter] = []
    for parameter in parameters[1:]:
        annotation = type_hints.get(parameter.name, parameter.annotation)
        if annotation is ToolContext:
            raise TypeError("Tool handlers may declare ToolContext only as the first parameter")
        if parameter.kind not in (
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            inspect.Parameter.KEYWORD_ONLY,
        ):
            raise TypeError("Tool handlers must use named parameters after ToolContext")

        visible_parameters.append(parameter)

    return tuple(visible_parameters)


def _schema_for_annotation(annotation: Any) -> dict[str, Any]:
    if annotation is inspect._empty:
        annotation = str
    return TypeAdapter(annotation).json_schema()


def _parse_google_docstring(
    docstring: str,
    visible_parameter_names: tuple[str, ...],
) -> tuple[str, dict[str, str]]:
    description_lines: list[str] = []
    argument_descriptions: dict[str, str] = {}
    expected_names = set(visible_parameter_names)
    lines = docstring.splitlines()
    line_index = 0
    section_header: str | None = None

    while line_index < len(lines):
        stripped = lines[line_index].strip()
        if stripped in _GOOGLE_DOCSTRING_SECTION_HEADERS:
            section_header = stripped
            break
        if stripped:
            description_lines.append(stripped)
        line_index += 1

    description = " ".join(description_lines)
    if section_header != "Args:":
        if visible_parameter_names:
            raise TypeError(_MISSING_ARGS_SECTION_ERROR)
        return description, {}

    line_index += 1

    current_argument: str | None = None
    while line_index < len(lines):
        line = lines[line_index]
        stripped = line.strip()
        line_index += 1

        if not stripped:
            current_argument = None
            continue
        if stripped in _GOOGLE_DOCSTRING_SECTION_HEADERS:
            break
        # Google-style Args entries must be indented under "Args:".
        if not line.startswith("    "):
            raise TypeError("Tool handler docstrings must use indented Google-style Args entries")

        if ":" in stripped:
            name, value = stripped.split(":", 1)
            if name.isidentifier():
                if name not in expected_names:
                    raise TypeError(f"Tool handler docstring documents unknown parameter: {name}")
                argument_description = value.strip()
                if not argument_description:
                    raise TypeError(
                        f"Tool handler docstring Args entry for {name!r} must include a description"
                    )
                current_argument = name
                argument_descriptions[current_argument] = argument_description
                continue

        if current_argument is None:
            raise TypeError(
                "Tool handler docstrings must use simple Google-style 'name: description' Args entries"
            )

        argument_descriptions[current_argument] = (
            f"{argument_descriptions[current_argument]} {stripped}".strip()
        )

    missing_arguments = [
        name for name in visible_parameter_names if name not in argument_descriptions
    ]
    if missing_arguments:
        raise TypeError(f"Tool handler docstring is missing Args entries for: {missing_arguments}")
    return description, argument_descriptions
