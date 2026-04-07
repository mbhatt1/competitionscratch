from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any

from aicomp_sdk.core.env.api import DiagnosticsEnv, EnvInteractionResult, EnvRunDiagnostics
from aicomp_sdk.guardrails.base import GuardrailBase


@dataclass
class _FakeEnv:
    seed: int = 123
    trace: Any = None
    tools: Any = None
    guardrail: GuardrailBase = field(default_factory=GuardrailBase)
    _messages: list[str] = field(default_factory=list)

    def reset(self) -> None:
        self._messages = []

    def interact(self, user_message: str, max_tool_hops: int = 8) -> EnvInteractionResult:
        del max_tool_hops
        self._messages.append(user_message)
        tool_events_added = 0 if user_message == "refuse" else 1
        agent_refused = user_message == "refuse"
        return EnvInteractionResult(
            seed=self.seed,
            total_tool_events=len([message for message in self._messages if message != "refuse"]),
            tool_events_added=tool_events_added,
            agent_turns=1,
            successful_tool_calls=tool_events_added,
            failed_tool_calls=0,
            agent_refused=agent_refused,
        )

    def export_trace_dict(self) -> dict[str, Any]:
        return {
            "seed": self.seed,
            "user_messages": list(self._messages),
            "tool_events": [],
            "egress": [],
        }

    def snapshot(self) -> dict[str, Any]:
        return {"messages": copy.deepcopy(self._messages)}

    def restore(self, snapshot: dict[str, Any]) -> None:
        self._messages = copy.deepcopy(snapshot["messages"])


def test_diagnostics_env_accumulates_seed_and_exploration_interactions() -> None:
    env = DiagnosticsEnv(_FakeEnv())

    seed_result = env.interact("open demo")
    explore_result = env.interact("branch 1")
    refusal_result = env.interact("refuse")

    assert seed_result.tool_events_added == 1
    assert explore_result.tool_events_added == 1
    assert refusal_result.agent_refused is True
    assert env.run_diagnostics.interactions == 3
    assert env.run_diagnostics.agent_turns == 3
    assert env.run_diagnostics.tool_calls == 2
    assert env.run_diagnostics.successful_tool_calls == 2
    assert env.run_diagnostics.failed_tool_calls == 0
    assert env.run_diagnostics.agent_refusals == 1


def test_diagnostics_env_uses_role_specific_env_run_diagnostics_type() -> None:
    env = DiagnosticsEnv(_FakeEnv())

    assert isinstance(env.run_diagnostics, EnvRunDiagnostics)


def test_diagnostics_env_delegates_snapshot_restore_and_export() -> None:
    env = DiagnosticsEnv(_FakeEnv())
    env.interact("open demo")
    snapshot = env.snapshot()
    env.interact("branch 1")

    env.restore(snapshot)

    assert env.export_trace_dict()["user_messages"] == ["open demo"]
    assert env.run_diagnostics.interactions == 2


def test_diagnostics_env_keeps_run_diagnostics_across_reset_and_restore() -> None:
    env = DiagnosticsEnv(_FakeEnv())
    env.interact("open demo")
    snapshot = env.snapshot()

    env.reset()
    env.restore(snapshot)

    assert env.export_trace_dict()["user_messages"] == ["open demo"]
    assert env.run_diagnostics.interactions == 1
    assert env.run_diagnostics.tool_calls == 1
