from __future__ import annotations

from typing import Final

from .email import EMAIL_TOOL_DEFS
from .fs import FS_TOOL_DEFS
from .http import HTTP_TOOL_DEFS
from .models import ToolDef
from .shell import SHELL_TOOL_DEFS
from .web import WEB_TOOL_DEFS


def build_tool_registry() -> dict[str, ToolDef]:
    registry: dict[str, ToolDef] = {}
    for tool_def in (
        *WEB_TOOL_DEFS,
        *FS_TOOL_DEFS,
        *SHELL_TOOL_DEFS,
        *EMAIL_TOOL_DEFS,
        *HTTP_TOOL_DEFS,
    ):
        if tool_def.name in registry:
            raise ValueError(f"Duplicate tool definition: {tool_def.name}")
        registry[tool_def.name] = tool_def
    return registry


TOOL_REGISTRY: Final[dict[str, ToolDef]] = build_tool_registry()
