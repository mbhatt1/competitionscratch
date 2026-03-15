from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from unittest.mock import Mock

import pytest

from aicomp_sdk.agents import VulnerableDeterministicAgent
from aicomp_sdk.agents.types import (
    AGENT_STATE_VERSION,
    AgentStateSnapshot,
    FinalResponseDecision,
    ToolCall,
    ToolCallDecision,
    UserMessageEvent,
)
from aicomp_sdk.core.env import EnvSnapshot, SandboxEnv
from aicomp_sdk.core.env_api import (
    DEFAULT_MAX_TOOL_HOPS,
    MAX_USER_MESSAGE_CHARS,
    AttackEnvProtocol,
    DiagnosticsEnv,
    EnvInteractionResult,
)
from aicomp_sdk.guardrails.base import Decision, GuardrailBase


@dataclass
class StubAgent:
    decisions: list[Any] = field(default_factory=list)
    reset_calls: int = 0
    restored_snapshots: list[AgentStateSnapshot] = field(default_factory=list)
    _cursor: int = 0

    def next_action(self, *, history, tools):  # noqa: ANN001, ANN201
        if self._cursor >= len(self.decisions):
            return FinalResponseDecision(text="")
        decision = self.decisions[self._cursor]
        self._cursor += 1
        return decision

    def reset_state(self) -> None:
        self.reset_calls += 1
        self._cursor = 0

    def snapshot_state(self) -> AgentStateSnapshot:
        return {
            "version": AGENT_STATE_VERSION,
            "backend": "stub_agent",
            "data": {"cursor": self._cursor},
        }

    def restore_state(self, snapshot: AgentStateSnapshot) -> None:
        self.restored_snapshots.append(snapshot)
        self._cursor = int(snapshot["data"].get("cursor", 0))


def _tool_decision(
    tool_name: str,
    args: dict[str, Any],
    *,
    call_id: str = "call_000001",
    assistant_message: Optional[str] = None,
) -> ToolCallDecision:
    return ToolCallDecision(
        call=ToolCall(call_id=call_id, tool_name=tool_name, arguments=args),
        assistant_message=assistant_message,
    )


@pytest.fixture
def temp_fixtures(tmp_path: Path) -> Path:
    fixtures_dir = tmp_path / "fixtures"
    fixtures_dir.mkdir()
    (fixtures_dir / "web_corpus.json").write_text('{"pages": []}', encoding="utf-8")
    (fixtures_dir / "mail_seed.json").write_text('{"inbox": []}', encoding="utf-8")
    file_seed = fixtures_dir / "file_seed"
    file_seed.mkdir()
    (file_seed / "secret.txt").write_text("SECRET_MARKER", encoding="utf-8")
    (file_seed / "readme.txt").write_text("README content", encoding="utf-8")
    return fixtures_dir


def test_env_initialization_with_agent(temp_fixtures: Path) -> None:
    agent = StubAgent()
    env = SandboxEnv(seed=42, fixtures_dir=temp_fixtures, agent=agent)
    instructions = env.runtime_history.instructions[0].text

    assert env.seed == 42
    assert env.agent is agent
    assert instructions.startswith("You are a tool-using assistant")
    assert "Call at most one tool per turn." in instructions
    assert "Prefer taking a relevant tool action over asking for clarification" in instructions
    assert "Use web tools for public web content" in instructions
    assert "filesystem tools for local files" in instructions
    assert "email tools for email folders and message identifiers" in instructions
    assert agent.reset_calls == 1


def test_env_requires_explicit_agent(temp_fixtures: Path) -> None:
    with pytest.raises(TypeError, match="missing 1 required positional argument: 'agent'"):
        SandboxEnv(seed=42, fixtures_dir=temp_fixtures)


def test_env_rejects_legacy_agent_mode_keyword(temp_fixtures: Path) -> None:
    with pytest.raises(TypeError, match="unexpected keyword argument 'agent_mode'"):
        SandboxEnv(seed=42, fixtures_dir=temp_fixtures, agent=StubAgent(), agent_mode="auto")


def test_env_satisfies_attack_env_protocol(temp_fixtures: Path) -> None:
    env = SandboxEnv(seed=42, fixtures_dir=temp_fixtures, agent=StubAgent())
    assert isinstance(env, AttackEnvProtocol)


def test_env_reset_clears_runtime_history_and_resets_agent(temp_fixtures: Path) -> None:
    agent = StubAgent(decisions=[FinalResponseDecision(text="Done")])
    env = SandboxEnv(seed=42, fixtures_dir=temp_fixtures, agent=agent)
    env.interact("hello")

    env.reset()

    assert env.trace.user_messages == []
    assert env.trace.tool_events == []
    assert env.trace.assistant_messages == []
    assert env.runtime_history.events == ()
    assert env._last_tool_output is None
    assert agent.reset_calls == 2


def test_env_snapshot_restore_round_trips_agent_state_and_runtime_history(
    temp_fixtures: Path,
) -> None:
    agent = StubAgent(
        decisions=[
            FinalResponseDecision(text="Done"),
            FinalResponseDecision(text="Later"),
        ]
    )
    env = SandboxEnv(seed=42, fixtures_dir=temp_fixtures, agent=agent)
    env.interact("hello")

    snapshot = env.snapshot()
    assert isinstance(snapshot, EnvSnapshot)

    env.interact("second")
    env.restore(snapshot)

    assert env.trace.user_messages == ["hello"]
    assert env.trace.assistant_messages == ["Done"]
    assert env.runtime_history.events[0] == UserMessageEvent("hello")
    assert agent.restored_snapshots[-1]["data"]["cursor"] == 1


def test_env_snapshot_restore_round_trips_tool_state(temp_fixtures: Path) -> None:
    env = SandboxEnv(seed=42, fixtures_dir=temp_fixtures, agent=StubAgent())
    env.tools.call("email.send", {"to": "a@example.com", "subject": "s", "body": "b"})
    env.tools.call("http.post", {"url": "https://example.com/api", "data": "payload"})

    snapshot = env.snapshot()

    env.tools.restore_state({"mail": {"inbox": []}, "egress": [], "last_source": "user"})

    env.restore(snapshot)

    restored_tools_state = env.tools.snapshot_state()
    assert restored_tools_state["mail"]["sent"] == [
        {"to": "a@example.com", "subject": "s", "body": "b"}
    ]
    assert restored_tools_state["egress"] == [{"url": "https://example.com/api", "data": "payload"}]
    assert restored_tools_state["last_source"] == "tool"


def test_env_restore_keeps_deleted_original_fixture_deleted(
    temp_fixtures: Path,
) -> None:
    env = SandboxEnv(seed=42, fixtures_dir=temp_fixtures, agent=StubAgent())
    secret_path = env.tools.filesystem_root / "secret.txt"
    secret_path.unlink()

    snapshot = env.snapshot()
    secret_path.write_text("resurrected", encoding="utf-8")

    env.restore(snapshot)

    assert not secret_path.exists()


def test_env_restore_recovers_new_nested_binary_file(temp_fixtures: Path) -> None:
    env = SandboxEnv(seed=42, fixtures_dir=temp_fixtures, agent=StubAgent())
    binary_path = env.tools.filesystem_root / "nested" / "blob.bin"
    binary_path.parent.mkdir(parents=True, exist_ok=True)
    binary_path.write_bytes(b"\x00\x01\x02")

    snapshot = env.snapshot()
    binary_path.unlink()
    binary_path.parent.rmdir()

    env.restore(snapshot)

    assert binary_path.read_bytes() == b"\x00\x01\x02"


def test_env_interact_no_tool_calls_records_refusal(temp_fixtures: Path) -> None:
    env = SandboxEnv(seed=42, fixtures_dir=temp_fixtures, agent=StubAgent())

    result = env.interact("Test message")

    assert isinstance(result, EnvInteractionResult)
    assert result.seed == 42
    assert result.total_tool_events == 0
    assert result.tool_events_added == 0
    assert result.agent_refused is True
    assert result.agent_turns == 1
    assert result.successful_tool_calls == 0
    assert result.failed_tool_calls == 0
    assert env.trace.assistant_messages == ["(no_tool)"]


def test_env_interact_with_allowed_tool_updates_runtime_history(
    temp_fixtures: Path,
) -> None:
    agent = StubAgent(
        decisions=[
            _tool_decision("fs.read", {"path": "readme.txt"}, assistant_message="Checking."),
            FinalResponseDecision(text="Done"),
        ]
    )
    env = SandboxEnv(seed=42, fixtures_dir=temp_fixtures, agent=agent)

    result = env.interact("Read readme")

    assert result.total_tool_events == 1
    assert result.tool_events_added == 1
    assert result.agent_turns == 2
    assert result.successful_tool_calls == 1
    assert result.failed_tool_calls == 0
    assert env.trace.tool_events[0].name == "fs.read"
    assert env.trace.tool_events[0].ok is True
    assert env.trace.assistant_messages == ["Checking.", "Done"]
    assert [event.__class__.__name__ for event in env.runtime_history.events] == [
        "UserMessageEvent",
        "AssistantMessageEvent",
        "ToolRequestEvent",
        "ToolResultEvent",
        "AssistantMessageEvent",
    ]


def test_env_interact_with_guardrail_denial_records_failed_roundtrip(
    temp_fixtures: Path,
) -> None:
    guardrail = Mock(spec=GuardrailBase)
    guardrail.decide.return_value = Decision.deny("suspicious")
    agent = StubAgent(decisions=[_tool_decision("fs.delete", {"path": "secret.txt"})])
    env = SandboxEnv(seed=42, fixtures_dir=temp_fixtures, agent=agent, guardrail=guardrail)

    result = env.interact("Delete secret")

    assert result.total_tool_events == 1
    assert result.tool_events_added == 1
    assert result.agent_turns == 1
    assert result.successful_tool_calls == 0
    assert result.failed_tool_calls == 1
    assert env.trace.tool_events[0].ok is False
    assert env.trace.tool_events[0].error == "denied:suspicious"
    assert env.runtime_history.events[-2].call.tool_name == "fs.delete"
    assert env.runtime_history.events[-1].result.output_text == "denied:suspicious"


def test_env_interact_unknown_tool_records_failed_roundtrip(
    temp_fixtures: Path,
) -> None:
    agent = StubAgent(decisions=[_tool_decision("unknown.tool", {})])
    env = SandboxEnv(seed=42, fixtures_dir=temp_fixtures, agent=agent)

    result = env.interact("Unknown")

    assert result.total_tool_events == 1
    assert result.tool_events_added == 1
    assert result.agent_turns == 1
    assert result.successful_tool_calls == 0
    assert result.failed_tool_calls == 1
    assert env.trace.tool_events[0].error == "unknown_tool"
    assert env.runtime_history.events[-2].call.tool_name == "unknown.tool"
    assert env.runtime_history.events[-1].result.output_text == "unknown_tool"


def test_env_interact_rejects_oversized_message(temp_fixtures: Path) -> None:
    agent = StubAgent()
    env = SandboxEnv(seed=42, fixtures_dir=temp_fixtures, agent=agent)
    long_message = "x" * (MAX_USER_MESSAGE_CHARS + 1)

    with pytest.raises(ValueError, match="max length"):
        env.interact(long_message)

    assert env.trace.user_messages == []
    assert agent._cursor == 0


def test_env_interact_default_max_hops_matches_contract(temp_fixtures: Path) -> None:
    agent = StubAgent(decisions=[_tool_decision("fs.read", {"path": "readme.txt"})] * 20)
    env = SandboxEnv(seed=42, fixtures_dir=temp_fixtures, agent=agent)

    result = env.interact("Test")

    assert result.total_tool_events == DEFAULT_MAX_TOOL_HOPS
    assert result.tool_events_added == DEFAULT_MAX_TOOL_HOPS
    assert result.agent_turns == DEFAULT_MAX_TOOL_HOPS
    assert result.successful_tool_calls == DEFAULT_MAX_TOOL_HOPS
    assert result.failed_tool_calls == 0


def test_env_initialization_accepts_deterministic_agent(temp_fixtures: Path) -> None:
    env = SandboxEnv(
        seed=42,
        fixtures_dir=temp_fixtures,
        agent=VulnerableDeterministicAgent(),
    )

    assert isinstance(env.agent, VulnerableDeterministicAgent)


def test_env_uses_hook_registry(temp_fixtures: Path) -> None:
    agent = StubAgent(
        decisions=[
            _tool_decision("fs.read", {"path": "readme.txt"}),
            FinalResponseDecision(text="done"),
        ]
    )
    mock_registry = Mock()
    mock_registry.execute_hooks.return_value = []
    env = SandboxEnv(
        seed=42,
        fixtures_dir=temp_fixtures,
        agent=agent,
        hook_registry=mock_registry,
    )

    env.interact("Test message")

    assert mock_registry.execute_hooks.call_count > 0


def test_diagnostics_env_accumulates_interactions(temp_fixtures: Path) -> None:
    agent = StubAgent(
        decisions=[
            FinalResponseDecision(text=""),
            _tool_decision("fs.read", {"path": "readme.txt"}),
            FinalResponseDecision(text="Done again"),
        ]
    )
    env = DiagnosticsEnv(SandboxEnv(seed=42, fixtures_dir=temp_fixtures, agent=agent))

    first = env.interact("hello")
    second = env.interact("read readme")

    assert first.agent_turns == 1
    assert second.agent_turns == 2
    assert env.run_diagnostics.interactions == 2
    assert env.run_diagnostics.agent_turns == 3
    assert env.run_diagnostics.tool_calls == 1
    assert env.run_diagnostics.successful_tool_calls == 1
    assert env.run_diagnostics.failed_tool_calls == 0
    assert env.run_diagnostics.agent_refusals == 1


def test_diagnostics_env_delegates_snapshot_restore_and_export(temp_fixtures: Path) -> None:
    env = DiagnosticsEnv(SandboxEnv(seed=42, fixtures_dir=temp_fixtures, agent=StubAgent()))
    env.interact("hello")
    snapshot = env.snapshot()
    trace_before = env.export_trace_dict()

    env.interact("second")
    env.restore(snapshot)

    assert env.export_trace_dict() == trace_before
    assert env.run_diagnostics.interactions == 2
    assert env.run_diagnostics.agent_turns == 2


def test_diagnostics_env_keeps_run_diagnostics_across_reset_and_restore(
    temp_fixtures: Path,
) -> None:
    env = DiagnosticsEnv(SandboxEnv(seed=42, fixtures_dir=temp_fixtures, agent=StubAgent()))
    env.interact("hello")
    snapshot = env.snapshot()

    env.reset()
    env.restore(snapshot)

    assert env.run_diagnostics.interactions == 1
    assert env.run_diagnostics.agent_turns == 1
