from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Callable, Mapping


class ToolSideEffect(StrEnum):
    """Coarse side-effect category for a tool call."""

    READ = "READ"
    WRITE = "WRITE"
    EXEC = "EXEC"
    NETWORK = "NETWORK"
    SHARE = "SHARE"
    AUTH = "AUTH"


class ToolScope(StrEnum):
    """Data or network boundary a tool is allowed to touch."""

    PUBLIC = "public"
    INTERNAL = "internal"
    LOCAL = "local"
    SECRETS = "secrets"
    EXTERNAL = "external"


@dataclass(frozen=True)
class RuntimeToolSpec:
    """Canonical runtime tool contract and shared schema source of truth.

    `parameters_json_schema` defines the single canonical argument schema used
    both for runtime validation and for backend registration projection.
    """

    name: str
    description: str
    side_effect: ToolSideEffect
    scope: ToolScope
    parameters_json_schema: Mapping[str, Any]


ToolCallResult = tuple[bool, str, str | None]
ToolHandler = Callable[..., ToolCallResult]


@dataclass(frozen=True)
class ToolDef:
    """Registered tool implementation and its guardrail-visible metadata."""

    name: str
    side_effect: ToolSideEffect
    scope: ToolScope
    handler: ToolHandler
