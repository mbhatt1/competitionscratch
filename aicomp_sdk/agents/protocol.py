from __future__ import annotations

from typing import Any, Optional, Protocol

from ..core.trace import Trace


class AgentProtocol(Protocol):
    def next_tool_call(
        self,
        trace: Trace,
        last_tool_output: Optional[str],
    ) -> Optional[dict[str, Any]]:
        pass
