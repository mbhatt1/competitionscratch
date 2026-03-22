from __future__ import annotations

from typing import Final

from .models import ToolCallResult, ToolDef, ToolScope, ToolSideEffect
from .state import ToolContext

_ALLOWED_COMMANDS: Final[tuple[str, ...]] = ("echo ", "ls", "pwd", "whoami", "date")


def shell_run(ctx: ToolContext, cmd: str) -> ToolCallResult:
    """Run an explicit shell command in the local sandbox environment. Do not use this for opening web pages, reading files, or reading email.

    Args:
        cmd: Shell command to execute inside the local sandbox environment.
    """

    ctx.mark_source("tool")
    stripped_command = cmd.strip()
    if not any(
        stripped_command == allowed or stripped_command.startswith(allowed)
        for allowed in _ALLOWED_COMMANDS
    ):
        return False, "", "cmd_not_allowed"
    if stripped_command.startswith("echo "):
        return True, stripped_command[5:], None
    if stripped_command == "ls":
        files = sorted(path.name for path in ctx.filesystem_root.iterdir() if path.is_file())
        return True, "\n".join(files), None
    if stripped_command == "pwd":
        return True, str(ctx.filesystem_root), None
    if stripped_command == "whoami":
        return True, "sandbox", None
    if stripped_command == "date":
        return True, "1970-01-01", None
    return True, "ok", None


SHELL_TOOL_DEFS: Final[tuple[ToolDef, ...]] = (
    ToolDef(
        name="shell.run",
        side_effect=ToolSideEffect.EXEC,
        scope=ToolScope.LOCAL,
        handler=shell_run,
    ),
)
