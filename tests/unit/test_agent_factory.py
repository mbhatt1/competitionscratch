from __future__ import annotations

from typing import Any

import pytest

from aicomp_sdk.agents import (
    AgentSelection,
    GPTOSSAgent,
    VulnerableDeterministicAgent,
    build_agent,
    build_agent_factory,
)
from aicomp_sdk.agents import factory as agent_factory
from aicomp_sdk.agents import (
    parse_agent_selection,
)


def test_parse_agent_selection_from_string() -> None:
    assert parse_agent_selection("auto") is AgentSelection.AUTO
    assert parse_agent_selection("gpt_oss") is AgentSelection.GPT_OSS


def test_parse_agent_selection_from_enum() -> None:
    assert parse_agent_selection(AgentSelection.OPENAI) is AgentSelection.OPENAI


def test_parse_agent_selection_rejects_invalid_value() -> None:
    with pytest.raises(ValueError, match="Unsupported agent selection: invalid"):
        parse_agent_selection("invalid")


def test_build_agent_deterministic_returns_expected_agent() -> None:
    agent = build_agent("deterministic")
    assert isinstance(agent, VulnerableDeterministicAgent)


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


def test_build_agent_factory_openai_requires_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    with pytest.raises(RuntimeError, match="OPENAI_API_KEY"):
        build_agent_factory("openai")


def test_build_agent_factory_auto_prefers_gpt_oss(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = object()

    monkeypatch.setenv("GPT_OSS_MODEL_PATH", "/fake/model")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setattr(agent_factory, "_create_gpt_oss_backend", lambda: backend)

    factory = build_agent_factory("auto")
    first = factory()
    second = factory()

    assert isinstance(first, GPTOSSAgent)
    assert isinstance(second, GPTOSSAgent)
    assert first is not second
    assert first.backend is backend
    assert second.backend is backend


def test_build_agent_factory_auto_falls_back_to_openai(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, Any]] = []

    class _FakeAgent:
        def __init__(self, api_key: str, verbose: bool) -> None:
            self.api_key = api_key
            self.verbose = verbose

        def next_tool_call(self, trace, last_tool_output):  # noqa: ANN001
            return None

    def fake_create_openai_agent(api_key: str, verbose: bool) -> _FakeAgent:
        calls.append({"api_key": api_key, "verbose": verbose})
        return _FakeAgent(api_key=api_key, verbose=verbose)

    monkeypatch.delenv("GPT_OSS_MODEL_PATH", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setattr(agent_factory, "_create_openai_agent", fake_create_openai_agent)

    factory = build_agent_factory("auto", verbose=False)
    first = factory()
    second = factory()

    assert first is not second
    assert len(calls) == 2
    assert calls[0] == {"api_key": "sk-test", "verbose": False}
    assert calls[1] == {"api_key": "sk-test", "verbose": False}


def test_build_agent_factory_gpt_oss_requires_model_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GPT_OSS_MODEL_PATH", raising=False)

    with pytest.raises(RuntimeError, match="GPT_OSS_MODEL_PATH"):
        build_agent_factory("gpt_oss")


def test_build_agent_factory_gpt_oss_returns_fresh_agents(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = object()

    monkeypatch.setenv("GPT_OSS_MODEL_PATH", "/fake/model")
    monkeypatch.setattr(agent_factory, "_create_gpt_oss_backend", lambda: backend)

    factory = build_agent_factory("gpt_oss")
    first = factory()
    second = factory()

    assert isinstance(first, GPTOSSAgent)
    assert isinstance(second, GPTOSSAgent)
    assert first is not second
    assert first.backend is backend
    assert second.backend is backend
