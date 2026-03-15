from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Mapping, Optional


class ToolSideEffect(str, Enum):
    READ = "READ"
    WRITE = "WRITE"
    EXEC = "EXEC"
    NETWORK = "NETWORK"
    SHARE = "SHARE"
    AUTH = "AUTH"


class ToolScope(str, Enum):
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


ToolCallResult = tuple[bool, str, Optional[str]]
ToolHandler = Callable[..., ToolCallResult]


@dataclass(frozen=True)
class ToolDef:
    name: str
    side_effect: ToolSideEffect
    scope: ToolScope
    handler: ToolHandler
