from __future__ import annotations

import sys
from types import SimpleNamespace
from typing import Any

import pytest

from aicomp_sdk.agents import (
    AgentSelection,
    GemmaAgent,
    GPTOSSAgent,
    InMemoryAgentDebugSink,
    VulnerableDeterministicAgent,
    build_agent,
    build_agent_factory,
)
from aicomp_sdk.agents import factory as agent_factory
from aicomp_sdk.agents import (
    coerce_agent_selection,
)
from aicomp_sdk.agents.gpt_oss_agent import build_gpt_oss_backend_config


class _BackendStub:
    config = build_gpt_oss_backend_config()

    def generate(self, request):  # noqa: ANN001, ANN201
        return None


def test_coerce_agent_selection_from_string() -> None:
    assert coerce_agent_selection("auto") is AgentSelection.AUTO
    assert coerce_agent_selection("gpt_oss") is AgentSelection.GPT_OSS
    assert coerce_agent_selection("gemma") is AgentSelection.GEMMA


def test_coerce_agent_selection_from_enum() -> None:
    assert coerce_agent_selection(AgentSelection.OPENAI) is AgentSelection.OPENAI


def test_coerce_agent_selection_rejects_invalid_value() -> None:
    with pytest.raises(ValueError, match="Unsupported agent selection: invalid"):
        coerce_agent_selection("invalid")


def test_build_agent_deterministic_returns_expected_agent() -> None:
    agent = build_agent("deterministic")
    assert isinstance(agent, VulnerableDeterministicAgent)


def test_build_agent_deterministic_threads_debug_sink() -> None:
    debug_sink = InMemoryAgentDebugSink()

    agent = build_agent("deterministic", debug_sink=debug_sink)

    assert isinstance(agent, VulnerableDeterministicAgent)
    assert agent._debug_sink is debug_sink


def test_build_agent_factory_returns_fresh_deterministic_instances() -> None:
    factory = build_agent_factory("deterministic")

    first = factory()
    second = factory()

    assert isinstance(first, VulnerableDeterministicAgent)
    assert isinstance(second, VulnerableDeterministicAgent)
    assert first is not second


def test_build_agent_factory_accepts_enum_selection() -> None:
    factory = build_agent_factory(AgentSelection.DETERMINISTIC)

    assert isinstance(factory(), VulnerableDeterministicAgent)


def test_create_openai_agent_constructs_sdk_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}
    client = object()
    debug_sink = InMemoryAgentDebugSink()

    class _FakeAgent:
        def __init__(
            self,
            *,
            client: object,
            verbose: bool,
            debug_sink: InMemoryAgentDebugSink | None = None,
        ) -> None:
            captured["client"] = client
            captured["verbose"] = verbose
            captured["debug_sink"] = debug_sink

    def fake_openai(*, api_key: str) -> object:
        captured["api_key"] = api_key
        return client

    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=fake_openai))
    monkeypatch.setattr(agent_factory, "OpenAIResponsesAgent", _FakeAgent)

    agent = agent_factory._create_openai_agent(
        "sk-test",
        verbose=True,
        debug_sink=debug_sink,
    )

    assert isinstance(agent, _FakeAgent)
    assert captured == {
        "api_key": "sk-test",
        "client": client,
        "verbose": True,
        "debug_sink": debug_sink,
    }


def test_create_openai_agent_surfaces_sdk_import_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace())

    with pytest.raises(RuntimeError, match="OpenAI SDK is not available"):
        agent_factory._create_openai_agent("sk-test", verbose=False)


def test_build_agent_factory_openai_requires_api_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    with pytest.raises(RuntimeError, match="OPENAI_API_KEY"):
        build_agent_factory("openai")


def test_build_agent_factory_auto_prefers_gpt_oss(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _BackendStub()

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setattr(agent_factory, "build_gpt_oss_backend", lambda: backend)

    factory = build_agent_factory("auto")
    first = factory()
    second = factory()

    assert isinstance(first, GPTOSSAgent)
    assert isinstance(second, GPTOSSAgent)
    assert first is not second
    assert first._delegate._backend is backend
    assert second._delegate._backend is backend


def test_build_agent_factory_auto_falls_back_to_openai(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, Any]] = []
    debug_sink = InMemoryAgentDebugSink()

    class _FakeAgent:
        def __init__(
            self,
            api_key: str,
            verbose: bool,
            debug_sink: InMemoryAgentDebugSink | None = None,
        ) -> None:
            self.api_key = api_key
            self.verbose = verbose
            self.debug_sink = debug_sink

        def next_action(self, *, history, tools):  # noqa: ANN001
            return None

        def reset_state(self) -> None:
            return None

        def snapshot_state(self):  # noqa: ANN201
            return {"version": 1, "backend": "fake_openai", "data": {}}

        def restore_state(self, snapshot) -> None:  # noqa: ANN001
            return None

    def fake_create_openai_agent(
        api_key: str,
        verbose: bool,
        debug_sink: InMemoryAgentDebugSink | None = None,
    ) -> _FakeAgent:
        calls.append(
            {
                "api_key": api_key,
                "verbose": verbose,
                "debug_sink": debug_sink,
            }
        )
        return _FakeAgent(
            api_key=api_key,
            verbose=verbose,
            debug_sink=debug_sink,
        )

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setattr(
        agent_factory,
        "build_gpt_oss_backend",
        lambda: (_ for _ in ()).throw(RuntimeError("not available")),
    )
    monkeypatch.setattr(agent_factory, "_create_openai_agent", fake_create_openai_agent)

    factory = build_agent_factory("auto", verbose=False, debug_sink=debug_sink)
    first = factory()
    second = factory()

    assert first is not second
    assert len(calls) == 2
    assert calls[0] == {
        "api_key": "sk-test",
        "verbose": False,
        "debug_sink": debug_sink,
    }
    assert calls[1] == {
        "api_key": "sk-test",
        "verbose": False,
        "debug_sink": debug_sink,
    }


def test_build_agent_factory_gpt_oss_surfaces_backend_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        agent_factory,
        "build_gpt_oss_backend",
        lambda: (_ for _ in ()).throw(RuntimeError("backend failed")),
    )

    with pytest.raises(RuntimeError, match="backend failed"):
        build_agent_factory("gpt_oss")


def test_build_agent_factory_gpt_oss_returns_fresh_agents(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _BackendStub()

    monkeypatch.setattr(agent_factory, "build_gpt_oss_backend", lambda: backend)

    factory = build_agent_factory("gpt_oss")
    first = factory()
    second = factory()

    assert isinstance(first, GPTOSSAgent)
    assert isinstance(second, GPTOSSAgent)
    assert first is not second
    assert first._delegate._backend is backend
    assert second._delegate._backend is backend


def test_build_agent_factory_gpt_oss_threads_debug_sink(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _BackendStub()
    debug_sink = InMemoryAgentDebugSink()

    monkeypatch.setattr(agent_factory, "build_gpt_oss_backend", lambda: backend)

    factory = build_agent_factory("gpt_oss", debug_sink=debug_sink)
    agent = factory()

    assert isinstance(agent, GPTOSSAgent)
    assert agent._delegate._debug_sink is debug_sink


def test_build_agent_factory_gemma_returns_fresh_agents(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _BackendStub()

    monkeypatch.setattr(agent_factory, "build_gemma_backend", lambda: backend)

    factory = build_agent_factory("gemma")
    first = factory()
    second = factory()

    assert isinstance(first, GemmaAgent)
    assert isinstance(second, GemmaAgent)
    assert first is not second
    assert first._delegate._backend is backend
    assert second._delegate._backend is backend


def test_build_agent_factory_gemma_threads_debug_sink(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _BackendStub()
    debug_sink = InMemoryAgentDebugSink()

    monkeypatch.setattr(agent_factory, "build_gemma_backend", lambda: backend)

    factory = build_agent_factory("gemma", debug_sink=debug_sink)
    agent = factory()

    assert isinstance(agent, GemmaAgent)
    assert agent._delegate._debug_sink is debug_sink
