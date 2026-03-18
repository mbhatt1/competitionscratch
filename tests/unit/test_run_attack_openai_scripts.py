from __future__ import annotations

import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

import run_attack_openai
import scripts.run_attack_openai as scripts_run_attack_openai
from examples.attacks import attack_goexplore_lpci


def test_root_openai_demo_selection_prefers_openai_when_key_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

    assert run_attack_openai._select_openai_demo_agent() == "openai"


def test_root_openai_demo_selection_falls_back_to_deterministic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    assert run_attack_openai._select_openai_demo_agent() == "deterministic"


def test_root_openai_demo_env_builds_sandbox_with_explicit_selection(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured: dict[str, Any] = {}
    fake_agent = object()

    def fake_build_agent(selection: str) -> object:
        captured["selection"] = selection
        return fake_agent

    class _FakeEnv:
        def __init__(self, *, seed: int, fixtures_dir: Path, agent: object, guardrail: object):
            captured["seed"] = seed
            captured["fixtures_dir"] = fixtures_dir
            captured["agent"] = agent
            captured["guardrail"] = guardrail

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setattr(run_attack_openai, "build_agent", fake_build_agent)
    monkeypatch.setattr(run_attack_openai, "SandboxEnv", _FakeEnv)

    run_attack_openai._build_demo_env(seed=42, fixtures_dir=tmp_path)

    assert captured["selection"] == "openai"
    assert captured["seed"] == 42
    assert captured["fixtures_dir"] == tmp_path
    assert captured["agent"] is fake_agent


def test_script_openai_demo_env_never_uses_auto(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    selections: list[str] = []

    def fake_build_agent(selection: str) -> object:
        selections.append(selection)
        return object()

    class _FakeEnv:
        def __init__(self, *, seed: int, fixtures_dir: Path, agent: object, guardrail: object):
            self.seed = seed
            self.fixtures_dir = fixtures_dir
            self.agent = agent
            self.guardrail = guardrail

    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(scripts_run_attack_openai, "build_agent", fake_build_agent)
    monkeypatch.setattr(scripts_run_attack_openai, "SandboxEnv", _FakeEnv)

    scripts_run_attack_openai._build_demo_env(seed=7, fixtures_dir=tmp_path)

    assert selections == ["deterministic"]


def test_root_main_fails_fast_when_attack_simple_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delitem(sys.modules, "attack_simple", raising=False)

    with pytest.raises(ModuleNotFoundError, match="attack_simple"):
        run_attack_openai.main()


def test_root_main_runs_through_shared_sandbox_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    fake_attack_module = ModuleType("attack_simple")

    class _FakeAttackAlgorithm:
        def run(self, env, config):  # noqa: ANN001, ANN201
            assert env == "fake-env"
            assert config == {"budget_s": 30, "steps": 10}
            return [
                {
                    "prompt": "demo",
                    "trace": {
                        "user_messages": ["hello"],
                        "tool_events": [],
                    },
                }
            ]

    setattr(fake_attack_module, "AttackAlgorithm", _FakeAttackAlgorithm)
    monkeypatch.setitem(sys.modules, "attack_simple", fake_attack_module)
    monkeypatch.setattr(run_attack_openai, "_build_demo_env", lambda **_: "fake-env")
    monkeypatch.setattr(
        run_attack_openai,
        "eval_predicates",
        lambda trace: [{"predicate": "EXFILTRATION", "severity": "high", "evidence": {}}],
    )
    monkeypatch.chdir(tmp_path)

    run_attack_openai.main()

    output = capsys.readouterr().out
    assert "LPCI ATTACK DEMO" in output
    assert "Validated breaches: 1/1" in output


def test_script_main_runs_through_shared_sandbox_env(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class _FakeAttackAlgorithm:
        def __init__(self, config):  # noqa: ANN001
            self.config = config
            self.last_run_details = [
                {
                    "trace": {
                        "user_messages": ["hello"],
                        "tool_events": [],
                    }
                }
            ]

        def run(self, env, config):  # noqa: ANN001, ANN201
            assert env == "fake-env"
            assert config.time_budget_s == 30
            return [{"trace": {"user_messages": ["hello"], "tool_events": []}}]

    monkeypatch.setattr(scripts_run_attack_openai, "_build_demo_env", lambda **_: "fake-env")
    monkeypatch.setattr(scripts_run_attack_openai, "AttackAlgorithm", _FakeAttackAlgorithm)
    monkeypatch.setattr(
        scripts_run_attack_openai,
        "eval_predicates",
        lambda trace: [{"predicate": "EXFILTRATION", "severity": "high", "evidence": {}}],
    )

    scripts_run_attack_openai.main()

    output = capsys.readouterr().out
    assert "GO-EXPLORE ATTACK DEMO" in output
    assert "Validated breaches: 1/1" in output


def test_example_openai_branch_uses_shared_sandbox_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured: dict[str, Any] = {}

    class _FakeEnv:
        def __init__(self, *, seed: int, fixtures_dir: Path, agent: object, guardrail: object):
            captured["seed"] = seed
            captured["fixtures_dir"] = fixtures_dir
            captured["agent"] = agent
            captured["guardrail"] = guardrail

    build_agent_calls: list[str] = []

    def fake_build_agent(selection: str) -> object:
        build_agent_calls.append(selection)
        return selection

    monkeypatch.delenv("GPT_OSS_MODEL_PATH", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setattr(attack_goexplore_lpci, "build_agent", fake_build_agent)
    monkeypatch.setattr(attack_goexplore_lpci, "Guardrail", lambda: "guardrail")
    monkeypatch.setattr(attack_goexplore_lpci, "SandboxEnv", _FakeEnv)

    attack_goexplore_lpci._build_demo_env(seed=123, fixtures_dir=tmp_path)

    assert build_agent_calls == ["openai"]
    assert captured["fixtures_dir"] == tmp_path
    assert captured["seed"] == 123


def test_example_local_model_branch_still_uses_auto(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured: dict[str, Any] = {}

    class _FakeEnv:
        def __init__(self, *, seed: int, fixtures_dir: Path, agent: object, guardrail: object):
            captured["agent"] = agent

    build_agent_calls: list[str] = []

    def fake_build_agent(selection: str) -> object:
        build_agent_calls.append(selection)
        return selection

    monkeypatch.setenv("GPT_OSS_MODEL_PATH", "/models/gpt-oss")
    monkeypatch.setattr(attack_goexplore_lpci, "build_agent", fake_build_agent)
    monkeypatch.setattr(attack_goexplore_lpci, "Guardrail", lambda: "guardrail")
    monkeypatch.setattr(attack_goexplore_lpci, "SandboxEnv", _FakeEnv)

    attack_goexplore_lpci._build_demo_env(seed=123, fixtures_dir=tmp_path)

    assert build_agent_calls == ["auto"]
    assert captured["agent"] == "auto"
