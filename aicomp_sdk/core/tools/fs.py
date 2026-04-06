from __future__ import annotations

from pathlib import Path
from typing import Final

from .models import ToolCallResult, ToolDef, ToolScope, ToolSideEffect
from .state import ToolContext


def fs_read(ctx: ToolContext, path: str) -> ToolCallResult:
    """Read a text file from the sandboxed filesystem by relative file path. Use this only for sandbox file paths, not web page identifiers or email message identifiers.

    Args:
        path: Relative sandbox file path, such as report.txt or logs/install.txt.
    """

    ctx.mark_source("file")
    resolved_path = _resolve_path(ctx, path)
    if _is_path_escape(ctx, resolved_path):
        return False, "", "path_escape"
    if not resolved_path.exists():
        return False, "", "not_found"
    if resolved_path.is_dir():
        return False, "", "is_directory"
    return True, resolved_path.read_text(encoding="utf-8"), None


def fs_write(ctx: ToolContext, path: str, content: str) -> ToolCallResult:
    """Write a text file in the sandboxed filesystem by relative file path. Use this for local sandbox files, not web pages or email.

    Args:
        path: Relative sandbox file path where the file should be written.
        content: UTF-8 text content to write to the local sandbox file.
    """

    ctx.mark_source("file")
    resolved_path = _resolve_path(ctx, path)
    if _is_path_escape(ctx, resolved_path):
        return False, "", "path_escape"
    resolved_path.parent.mkdir(parents=True, exist_ok=True)
    resolved_path.write_text(content, encoding="utf-8")
    return True, "ok", None


def fs_delete(ctx: ToolContext, path: str) -> ToolCallResult:
    """Delete a file from the sandboxed filesystem by relative file path. Use this only for local sandbox files, not web pages or email.

    Args:
        path: Relative sandbox file path to remove from the local filesystem.
    """

    ctx.mark_source("file")
    resolved_path = _resolve_path(ctx, path)
    if _is_path_escape(ctx, resolved_path):
        return False, "", "path_escape"
    if resolved_path.exists():
        resolved_path.unlink()
        return True, "ok", None
    return False, "", "not_found"


def _resolve_path(ctx: ToolContext, path: str) -> Path:
    return (ctx.filesystem_root / path.lstrip("/")).resolve()


def _is_path_escape(ctx: ToolContext, path: Path) -> bool:
    return not path.is_relative_to(ctx.filesystem_root.resolve())


FS_TOOL_DEFS: Final[tuple[ToolDef, ...]] = (
    ToolDef(
        name="fs.read",
        side_effect=ToolSideEffect.READ,
        scope=ToolScope.LOCAL,
        handler=fs_read,
    ),
    ToolDef(
        name="fs.write",
        side_effect=ToolSideEffect.WRITE,
        scope=ToolScope.LOCAL,
        handler=fs_write,
    ),
    ToolDef(
        name="fs.delete",
        side_effect=ToolSideEffect.WRITE,
        scope=ToolScope.LOCAL,
        handler=fs_delete,
    ),
)
