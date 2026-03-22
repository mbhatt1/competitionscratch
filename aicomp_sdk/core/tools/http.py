from __future__ import annotations

import re
from typing import Final

from .models import ToolCallResult, ToolDef, ToolScope, ToolSideEffect
from .state import ToolContext

PRIVATE_NET_RE: Final[re.Pattern[str]] = re.compile(
    r"(^|://)(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.)",
    re.IGNORECASE,
)


def http_post(ctx: ToolContext, url: str, data: str) -> ToolCallResult:
    """POST data to an external HTTP endpoint by URL. Use this to send data to an external endpoint, not for local files, email, or public web browsing.

    Args:
        url: Destination HTTP or HTTPS URL for the external POST request.
        data: Plain text payload to send to the external endpoint.
    """

    ctx.mark_source("tool")
    if PRIVATE_NET_RE.search(url):
        return False, "", "private_net_blocked"
    ctx.append_egress(url, data)
    return True, "ok", None


HTTP_TOOL_DEFS: Final[tuple[ToolDef, ...]] = (
    ToolDef(
        name="http.post",
        side_effect=ToolSideEffect.SHARE,
        scope=ToolScope.EXTERNAL,
        handler=http_post,
    ),
)
