from __future__ import annotations

import json
from typing import Final

from .models import (
    ToolCallResult,
    ToolDef,
    ToolScope,
    ToolSideEffect,
)
from .state import ToolContext

EMAIL_LIST_DEFAULT_LIMIT: Final[int] = 20
EMAIL_LIST_MAX_LIMIT: Final[int] = 50


def email_list(
    ctx: ToolContext,
    folder: str,
    limit: int | None = EMAIL_LIST_DEFAULT_LIMIT,
    cursor: str | None = None,
) -> ToolCallResult:
    """List a bounded page of shallow message summaries from a local email folder. Use this to discover message identifiers before calling email.read on a specific message.

    Args:
        folder: Local email folder name, such as inbox or archive.
        limit: Maximum number of message summaries to return for this page. Defaults to 20 and is capped at 50.
        cursor: Stringified offset cursor for the next page. Omit or pass null to start at the beginning of the folder.
    """

    ctx.mark_source("email")
    folder_messages = ctx.get_mail_folder(folder)
    if folder_messages is None:
        return False, "", "folder_not_found"

    limit_arg = limit
    if limit_arg is None:
        page_limit = EMAIL_LIST_DEFAULT_LIMIT
    elif isinstance(limit_arg, bool) or not isinstance(limit_arg, int) or limit_arg <= 0:
        return False, "", "invalid_limit"
    else:
        page_limit = min(limit_arg, EMAIL_LIST_MAX_LIMIT)

    cursor_arg = cursor
    if cursor_arg is None:
        start = 0
    elif isinstance(cursor_arg, str) and cursor_arg.isdecimal():
        start = int(cursor_arg)
    else:
        return False, "", "invalid_cursor"

    if start >= len(folder_messages):
        page_messages: list[dict[str, str]] = []
        next_cursor = None
        has_more = False
    else:
        end = min(start + page_limit, len(folder_messages))
        page_messages = [
            {
                "id": message["id"],
                "from": message["from"],
                "subject": message["subject"],
            }
            for message in folder_messages[start:end]
        ]
        has_more = end < len(folder_messages)
        next_cursor = str(end) if has_more else None

    return (
        True,
        json.dumps(
            {
                "folder": folder,
                "emails": page_messages,
                "next_cursor": next_cursor,
                "has_more": has_more,
            }
        ),
        None,
    )


def email_read(ctx: ToolContext, id: str) -> ToolCallResult:
    """Read a local email message by known message identifier. Use this only when you already know the message identifier.

    Args:
        id: Known email message identifier, typically one returned by email.list.
    """

    ctx.mark_source("email")
    message = None
    for folder_messages in ctx.iter_mail_folders():
        if isinstance(folder_messages, list):
            message = next((item for item in folder_messages if item["id"] == id), None)
            if message is not None:
                break
    if message is None:
        return False, "", "not_found"
    return True, json.dumps(message), None


def email_send(ctx: ToolContext, to: str, subject: str, body: str) -> ToolCallResult:
    """Send an email to an external recipient by email address. Use this to share content externally, not to inspect local email folders or messages.

    Args:
        to: External recipient email address.
        subject: Subject line for the outgoing email.
        body: Plain text body content for the outgoing email.
    """

    ctx.mark_source("tool")
    ctx.append_sent_email(to, subject, body)
    return True, "sent", None


EMAIL_TOOL_DEFS: Final[tuple[ToolDef, ...]] = (
    ToolDef(
        name="email.list",
        side_effect=ToolSideEffect.READ,
        scope=ToolScope.LOCAL,
        handler=email_list,
    ),
    ToolDef(
        name="email.read",
        side_effect=ToolSideEffect.READ,
        scope=ToolScope.LOCAL,
        handler=email_read,
    ),
    ToolDef(
        name="email.send",
        side_effect=ToolSideEffect.SHARE,
        scope=ToolScope.EXTERNAL,
        handler=email_send,
    ),
)
