from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import run_attack_openai
import scripts.goexplore_lpci_demo as goexplore_lpci_demo
import scripts.run_attack_openai as scripts_run_attack_openai


def test_root_openai_demo_selection_prefers_openai_when_key_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(scripts_run_attack_openai, "_select_openai_demo_agent", lambda: "openai")

    assert run_attack_openai._select_openai_demo_agent() == "openai"


def test_root_openai_demo_selection_falls_back_to_deterministic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        scripts_run_attack_openai, "_select_openai_demo_agent", lambda: "deterministic"
    )

    assert run_attack_openai._select_openai_demo_agent() == "deterministic"


def test_root_openai_demo_env_builds_sandbox_with_explicit_selection(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured: dict[str, Any] = {}

    def fake_build_demo_env(*, seed: int, fixtures_dir: Path) -> object:
        captured["seed"] = seed
        captured["fixtures_dir"] = fixtures_dir
        return "fake-env"

    monkeypatch.setattr(scripts_run_attack_openai, "_build_demo_env", fake_build_demo_env)

    assert run_attack_openai._build_demo_env(seed=42, fixtures_dir=tmp_path) == "fake-env"
    assert captured == {"seed": 42, "fixtures_dir": tmp_path}


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


def test_root_main_runs_through_shared_sandbox_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def fake_main() -> None:
        calls.append("delegated")

    monkeypatch.setattr(scripts_run_attack_openai, "main", fake_main)

    run_attack_openai.main()

    assert calls == ["delegated"]


def test_script_main_runs_through_shared_sandbox_env(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    captured: dict[str, Any] = {}

    def fake_build_agent_factory(selection: str) -> object:
        captured["agent_selection"] = selection
        return "fake-agent-factory"

    def fake_eval_attack(
        attack_cls, budget_s, agent_factory, env_selection, **kwargs
    ):  # noqa: ANN001, ANN202
        captured["attack_cls"] = attack_cls
        captured["budget_s"] = budget_s
        captured["agent_factory"] = agent_factory
        captured["env_selection"] = env_selection
        captured["kwargs"] = kwargs
        return [
            {
                "trace": {
                    "user_messages": ["hello"],
                    "tool_events": [],
                },
                "predicates": [{"predicate": "EXFILTRATION", "severity": "high", "evidence": {}}],
            }
        ]

    monkeypatch.setattr(scripts_run_attack_openai, "build_agent_factory", fake_build_agent_factory)
    monkeypatch.setattr(scripts_run_attack_openai, "eval_attack", fake_eval_attack)

    scripts_run_attack_openai.main()

    options = captured["kwargs"]["options"]
    assert captured["attack_cls"] is scripts_run_attack_openai.AttackAlgorithm
    assert captured["budget_s"] == 30
    assert captured["agent_factory"] == "fake-agent-factory"
    assert captured["agent_selection"] == scripts_run_attack_openai._select_openai_demo_agent()
    assert captured["env_selection"] == "sandbox"
    assert captured["kwargs"]["fixtures_dir"] == scripts_run_attack_openai.repo_root / "fixtures"
    assert options.run_config.time_budget_s == 30
    assert options.run_config.max_steps == 100
    assert options.attack_config == {"max_turns": 6, "branch_batch": 8}
    assert options.env_seed == 42
    assert options.guardrail_factory is scripts_run_attack_openai.BaselineGuardrail

    output = capsys.readouterr().out
    assert "GO-EXPLORE ATTACK DEMO" in output
    assert "Validated breaches: 1/1" in output


def test_goexplore_lpci_demo_openai_branch_uses_shared_sandbox_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured: dict[str, Any] = {}

    class _FakeEnv:
        def __init__(
            self,
            *,
            seed: int,
            fixtures_dir: Path,
            agent: object,
            guardrail: object,
            hook_registry: object,
        ):
            captured["seed"] = seed
            captured["fixtures_dir"] = fixtures_dir
            captured["agent"] = agent
            captured["guardrail"] = guardrail
            captured["hook_registry"] = hook_registry

    build_agent_calls: list[str] = []

    def fake_build_agent(selection: str) -> object:
        build_agent_calls.append(selection)
        return selection

    monkeypatch.delenv("GPT_OSS_MODEL_PATH", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setattr(goexplore_lpci_demo, "build_agent", fake_build_agent)
    monkeypatch.setattr(goexplore_lpci_demo, "Guardrail", lambda: "guardrail")
    monkeypatch.setattr(goexplore_lpci_demo, "SandboxEnv", _FakeEnv)

    goexplore_lpci_demo._build_demo_env(seed=123, fixtures_dir=tmp_path)

    assert build_agent_calls == ["openai"]
    assert captured["fixtures_dir"] == tmp_path
    assert captured["seed"] == 123


def test_goexplore_lpci_demo_local_model_branch_still_uses_auto(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured: dict[str, Any] = {}

    class _FakeEnv:
        def __init__(
            self,
            *,
            seed: int,
            fixtures_dir: Path,
            agent: object,
            guardrail: object,
            hook_registry: object,
        ):
            del seed, fixtures_dir, guardrail
            captured["agent"] = agent
            captured["hook_registry"] = hook_registry

    build_agent_calls: list[str] = []

    def fake_build_agent(selection: str) -> object:
        build_agent_calls.append(selection)
        return selection

    monkeypatch.setenv("GPT_OSS_MODEL_PATH", "/models/gpt-oss")
    monkeypatch.setattr(goexplore_lpci_demo, "build_agent", fake_build_agent)
    monkeypatch.setattr(goexplore_lpci_demo, "Guardrail", lambda: "guardrail")
    monkeypatch.setattr(goexplore_lpci_demo, "SandboxEnv", _FakeEnv)

    goexplore_lpci_demo._build_demo_env(seed=123, fixtures_dir=tmp_path)

    assert build_agent_calls == ["auto"]
    assert captured["agent"] == "auto"
