from __future__ import annotations

import json
from typing import Final

from .models import ToolCallResult, ToolDef, ToolScope, ToolSideEffect
from .state import ToolContext


def web_search(ctx: ToolContext, query: str) -> ToolCallResult:
    """Search public pages in the offline web corpus by keywords or title when you do not already know the page identifier.

    Args:
        query: Keywords or page title text used to find a public page in the offline web corpus.
    """

    ctx.mark_source("web")
    lowered_query = query.lower()
    hits = []
    for page in ctx.web_pages:
        if lowered_query in page["title"].lower() or lowered_query in page["content"].lower():
            hits.append({"id": page["id"], "title": page["title"]})

    hits.sort(key=lambda hit: hit["id"])
    hits = hits[:10]
    if not hits:
        hits = [{"id": "page_0", "title": "Welcome"}]
    return True, json.dumps({"results": hits}), None


def web_open(ctx: ToolContext, id: str) -> ToolCallResult:
    """Open a public page from the offline web corpus by known page identifier. Do not use this for local file paths or email message identifiers.

    Args:
        id: Known offline web page identifier, such as one returned by web.search.
    """

    ctx.mark_source("web")
    page = next((item for item in ctx.web_pages if item["id"] == id), None)
    if page is None:
        return False, "", "not_found"
    return True, page["content"], None


WEB_TOOL_DEFS: Final[tuple[ToolDef, ...]] = (
    ToolDef(
        name="web.search",
        side_effect=ToolSideEffect.NETWORK,
        scope=ToolScope.PUBLIC,
        handler=web_search,
    ),
    ToolDef(
        name="web.open",
        side_effect=ToolSideEffect.NETWORK,
        scope=ToolScope.PUBLIC,
        handler=web_open,
    ),
)
