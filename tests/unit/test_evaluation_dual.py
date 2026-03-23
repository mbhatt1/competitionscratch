from __future__ import annotations
# mypy: disable-error-code="unused-ignore,attr-defined"

import json
import sys
from importlib import import_module
from pathlib import Path
from tempfile import TemporaryDirectory
from types import ModuleType

import pytest

import aicomp_sdk.evaluation.ops as evaluation_core
import aicomp_sdk.evaluation.submissions as evaluation_submissions
import aicomp_sdk.scoring as scoring
from aicomp_sdk.attacks import AttackAlgorithmBase, AttackCandidate, AttackRunConfig
from aicomp_sdk.core.env.api import EnvSelection
from aicomp_sdk.evaluation.budget_policy import (
    DEFAULT_ATTACK_BUDGET_S,
    DEFAULT_DEFENSE_BUDGET_S,
)
from aicomp_sdk.guardrails.base import Decision, GuardrailBase


class _StubAttackAlgorithm(AttackAlgorithmBase):
    def run(self, env, config: AttackRunConfig) -> list[AttackCandidate]:  # type: ignore[no-untyped-def]
        return []


class _StubGuardrail(GuardrailBase):
    def decide(self, tool_name, tool_args, context) -> Decision:  # type: ignore[no-untyped-def]
        return Decision.allow("stub")


def _stub_attack_module() -> ModuleType:
    module = ModuleType("user_attack")
    module.AttackAlgorithm = _StubAttackAlgorithm
    return module


def _stub_guardrail_module() -> ModuleType:
    module = ModuleType("user_guardrail")
    module.Guardrail = _StubGuardrail
    return module


def _artifact_paths(tmp_path: Path) -> tuple[Path, Path, Path]:
    artifacts_dir = tmp_path / "artifacts"
    return artifacts_dir, artifacts_dir / "score.txt", artifacts_dir / "report.json"


def _fake_load_from_zip(zip_path, module_name, file_name):  # type: ignore[no-untyped-def]
    del zip_path, module_name
    tmp = TemporaryDirectory()
    if file_name == "attack.py":
        return _stub_attack_module(), tmp
    return _stub_guardrail_module(), tmp


def _empty_attack_summary(findings: object) -> dict[str, float | int]:
    del findings
    return {
        "score": 0.0,
        "score_raw": 0.0,
        "findings_count": 0,
        "unique_cells": 0,
    }


def _neutral_defense_report() -> dict[str, int]:
    return {"breach_count": 0, "false_positives": 0, "benign_trials": 7}


def _run_evaluate_cli() -> int:
    sys.argv = [sys.argv[0], "evaluate", *sys.argv[1:]]
    return import_module("aicomp_sdk.cli.main").main()


def test_dual_evaluator_passes_fixtures_override(tmp_path, monkeypatch) -> None:
    submission_zip = tmp_path / "submission.zip"
    submission_zip.write_bytes(b"placeholder")
    fixtures_dir = tmp_path / "fixtures"
    fixtures_dir.mkdir()
    artifacts_dir, _, report_path = _artifact_paths(tmp_path)

    monkeypatch.setattr(evaluation_submissions, "load_from_zip", _fake_load_from_zip)

    captured = {}

    def fake_eval_attack(
        attack_cls,
        budget_s,
        agent_factory,
        env_selection,
        attack_seed=123,
        fixtures_dir=None,
        output_controller=None,
        *,
        options=None,
    ):  # type: ignore[no-untyped-def]
        del options
        captured["attack_fixtures_dir"] = fixtures_dir
        captured["attack_agent_factory"] = agent_factory
        captured["attack_budget_s"] = budget_s
        captured["attack_env_selection"] = env_selection
        return []

    def fake_eval_defense(
        guardrail_cls,
        budget_s,
        agent_factory=None,
        env_selection=None,
        attack_seed=123,
        benign_seed=999,
        fixtures_dir=None,
        output_controller=None,
        *,
        options=None,
    ):  # type: ignore[no-untyped-def]
        del options
        captured["defense_fixtures_dir"] = fixtures_dir
        captured["defense_agent_factory"] = agent_factory
        captured["defense_budget_s"] = budget_s
        captured["defense_env_selection"] = env_selection
        return _neutral_defense_report()

    monkeypatch.setattr(evaluation_core, "eval_attack", fake_eval_attack)
    monkeypatch.setattr(evaluation_core, "eval_defense", fake_eval_defense)
    monkeypatch.setattr(scoring, "score_defense", lambda report: 1000.0)
    monkeypatch.setattr(
        scoring, "get_score_breakdown", lambda findings, report: {"attack_mode": "normalized"}
    )
    monkeypatch.setattr(
        evaluation_core,
        "summarize_attack_findings",
        _empty_attack_summary,
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "evaluation.py",
            "dual",
            str(submission_zip),
            "--fixtures-dir",
            str(fixtures_dir),
            "--artifacts-dir",
            str(artifacts_dir),
        ],
    )

    _run_evaluate_cli()

    assert captured["attack_fixtures_dir"] == fixtures_dir.resolve()
    assert captured["defense_fixtures_dir"] == fixtures_dir.resolve()
    assert callable(captured["attack_agent_factory"])
    assert callable(captured["defense_agent_factory"])
    assert captured["attack_budget_s"] == DEFAULT_ATTACK_BUDGET_S
    assert captured["defense_budget_s"] == DEFAULT_DEFENSE_BUDGET_S
    assert captured["attack_env_selection"] == "sandbox"
    assert captured["defense_env_selection"] == "sandbox"
    details = json.loads(report_path.read_text(encoding="utf-8"))
    assert details["env_selection"] == "sandbox"


def test_dual_evaluator_passes_explicit_env_selection(tmp_path, monkeypatch) -> None:
    submission_zip = tmp_path / "submission.zip"
    submission_zip.write_bytes(b"placeholder")
    artifacts_dir, _, _ = _artifact_paths(tmp_path)

    monkeypatch.setattr(evaluation_submissions, "load_from_zip", _fake_load_from_zip)

    captured = {}

    def fake_eval_attack(
        attack_cls,
        budget_s,
        agent_factory,
        env_selection,
        attack_seed=123,
        fixtures_dir=None,
        output_controller=None,
        *,
        options=None,
    ):  # type: ignore[no-untyped-def]
        del attack_cls, budget_s, agent_factory, attack_seed, fixtures_dir, output_controller, options
        captured["attack_env_selection"] = env_selection
        return []

    def fake_eval_defense(
        guardrail_cls,
        budget_s,
        agent_factory=None,
        env_selection=None,
        attack_seed=123,
        benign_seed=999,
        fixtures_dir=None,
        output_controller=None,
        *,
        options=None,
    ):  # type: ignore[no-untyped-def]
        del (
            guardrail_cls,
            budget_s,
            agent_factory,
            attack_seed,
            benign_seed,
            fixtures_dir,
            output_controller,
            options,
        )
        captured["defense_env_selection"] = env_selection
        return _neutral_defense_report()

    monkeypatch.setattr(evaluation_core, "eval_attack", fake_eval_attack)
    monkeypatch.setattr(evaluation_core, "eval_defense", fake_eval_defense)
    monkeypatch.setattr(scoring, "score_defense", lambda report: 1000.0)
    monkeypatch.setattr(
        scoring, "get_score_breakdown", lambda findings, report: {"attack_mode": "normalized"}
    )
    monkeypatch.setattr(
        evaluation_core,
        "summarize_attack_findings",
        _empty_attack_summary,
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "evaluation.py",
            "dual",
            str(submission_zip),
            "--env",
            "gym",
            "--artifacts-dir",
            str(artifacts_dir),
        ],
    )

    _run_evaluate_cli()

    assert captured["attack_env_selection"] is EnvSelection.GYM
    assert captured["defense_env_selection"] is EnvSelection.GYM


def test_dual_default_output_suppresses_eval_noise(
    tmp_path,
    monkeypatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    submission_zip = tmp_path / "submission.zip"
    submission_zip.write_bytes(b"placeholder")
    artifacts_dir, _, _ = _artifact_paths(tmp_path)

    monkeypatch.setattr(evaluation_submissions, "load_from_zip", _fake_load_from_zip)

    def fake_eval_attack(*args, **kwargs):  # type: ignore[no-untyped-def]
        print("attack noise stdout")
        print("attack noise stderr", file=sys.stderr)
        return []

    def fake_eval_defense(*args, **kwargs):  # type: ignore[no-untyped-def]
        print("defense noise stdout")
        print("defense noise stderr", file=sys.stderr)
        return _neutral_defense_report()

    monkeypatch.setattr(evaluation_core, "eval_attack", fake_eval_attack)
    monkeypatch.setattr(evaluation_core, "eval_defense", fake_eval_defense)
    monkeypatch.setattr(scoring, "score_defense", lambda report: 1000.0)
    monkeypatch.setattr(
        scoring, "get_score_breakdown", lambda findings, report: {"attack_mode": "normalized"}
    )
    monkeypatch.setattr(
        evaluation_core,
        "summarize_attack_findings",
        _empty_attack_summary,
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "evaluation.py",
            "dual",
            str(submission_zip),
            "--artifacts-dir",
            str(artifacts_dir),
        ],
    )

    _run_evaluate_cli()

    captured = capsys.readouterr()
    assert "FINAL RESULTS" in captured.out
    assert "attack noise stdout" not in captured.out
    assert "attack noise stdout" not in captured.err
    assert "defense noise stderr" not in captured.err


def test_dual_evaluator_writes_balanced_framework_phase_events(
    tmp_path,
    monkeypatch,
) -> None:
    submission_zip = tmp_path / "submission.zip"
    submission_zip.write_bytes(b"placeholder")
    artifacts_dir, _, _ = _artifact_paths(tmp_path)
    framework_events_path = artifacts_dir / "framework.jsonl"

    monkeypatch.setattr(evaluation_submissions, "load_from_zip", _fake_load_from_zip)
    monkeypatch.setattr(evaluation_core, "eval_attack", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        evaluation_core,
        "eval_defense",
        lambda *args, **kwargs: _neutral_defense_report(),
    )
    monkeypatch.setattr(scoring, "score_defense", lambda report: 1000.0)
    monkeypatch.setattr(
        scoring, "get_score_breakdown", lambda findings, report: {"attack_mode": "normalized"}
    )
    monkeypatch.setattr(
        evaluation_core,
        "summarize_attack_findings",
        lambda findings: {
            "score": 100.0,
            "score_raw": 100.0,
            "findings_count": 2,
            "unique_cells": 1,
        },
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "evaluation.py",
            "dual",
            str(submission_zip),
            "--artifacts-dir",
            str(artifacts_dir),
            "--save-framework-events",
        ],
    )

    _run_evaluate_cli()

    framework_events = [
        json.loads(line)
        for line in framework_events_path.read_text(encoding="utf-8").splitlines()
    ]
    assert [event["event"] for event in framework_events] == [
        "phase_start",
        "phase_end",
        "phase_start",
        "phase_end",
    ]
    assert [event["phase"] for event in framework_events] == [
        "dual_offense_evaluation",
        "dual_offense_evaluation",
        "dual_defense_evaluation",
        "dual_defense_evaluation",
    ]
    assert framework_events[1]["fields"]["findings_count"] == 2
    assert framework_events[1]["fields"]["score"] == 100.0
    assert framework_events[2]["fields"]["offense_score"] == 100.0
