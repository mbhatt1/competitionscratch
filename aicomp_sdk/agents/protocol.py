from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from aicomp_sdk.agents.types import AgentDecision, AgentStateSnapshot, AgentToolSpec
from aicomp_sdk.core.runtime_history import RuntimeHistory


class AgentProtocol(Protocol):
    """Common agent contract for all evaluator backends."""

    def next_action(
        self,
        *,
        history: RuntimeHistory,
        tools: Sequence[AgentToolSpec],
    ) -> AgentDecision:
        """Choose the next action from canonical runtime history."""

    def reset_state(self) -> None:
        """Clear provider-private runtime state."""

    def snapshot_state(self) -> AgentStateSnapshot:
        """Return a restorable provider-private snapshot."""

    def restore_state(self, snapshot: AgentStateSnapshot) -> None:
        """Restore provider-private state from a snapshot."""
