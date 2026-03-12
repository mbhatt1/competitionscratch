from __future__ import annotations

import json
from contextlib import ExitStack, nullcontext
from pathlib import Path
from types import SimpleNamespace

import aicomp_sdk.evaluation_core as evaluation_core
from aicomp_sdk.agents import AgentSelection
from aicomp_sdk.cli.commands import test as test_command
from aicomp_sdk.core.env_api import EnvSelection


def _redteam_result(
    *,
    score: float,
    score_raw: float,
    findings_count: int,
    unique_cells: int,
    agent_selection: object,
    env_selection: object,
) -> dict[str, object]:
    return {
        "track": "redteam",
        "attack": {
            "score": score,
            "score_raw": score_raw,
            "findings_count": findings_count,
            "unique_cells": unique_cells,
            "time_taken": 0.1,
        },
        "final_score": score,
        "submission_type": "attack_only",
        "scoring_mode": "normalized",
        "agent_selection": agent_selection,
        "env_selection": env_selection,
    }


def _dual_result(*, agent_selection: object, env_selection: object) -> dict[str, object]:
    return {
        "track": "dual",
        "attack": {
            "score": 10.0,
            "score_raw": 3.0,
            "findings_count": 1,
            "unique_cells": 1,
            "time_taken": 0.1,
        },
        "defense": {
            "score": 800.0,
            "breach_count": 0,
            "false_positives": 0,
            "benign_trials": 7,
            "false_positive_rate": 0.0,
            "time_taken": 0.1,
        },
        "final_score": 810.0,
        "scoring_mode": "normalized",
        "submission_type": "dual_track",
        "agent_selection": agent_selection,
        "env_selection": env_selection,
    }


def _defense_result(*, agent_selection: object, env_selection: object) -> dict[str, object]:
    return {
        "track": "defense",
        "defense": {
            "score": 900.0,
            "breach_count": 0,
            "false_positives": 0,
            "benign_trials": 7,
            "false_positive_rate": 0.0,
            "time_taken": 0.1,
        },
        "final_score": 900.0,
        "submission_type": "guardrail_only",
        "agent_selection": agent_selection,
        "env_selection": env_selection,
    }


def test_run_test_auto_selects_redteam_for_attack_py(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    attack_file = tmp_path / "attack.py"
    fixtures_dir = tmp_path / "fixtures"
    fixtures_dir.mkdir()
    attack_file.write_text(
        "class AttackAlgorithm:\n    pass\n",
        encoding="utf-8",
    )

    captured: dict[str, object] = {}

    monkeypatch.setattr(
        test_command,
        "_load_track_modules",
        lambda stack, submission_path, track: (object, None),
    )

    def fake_run_redteam_evaluation(  # noqa: ANN202
        attack_cls,
        attack_budget_s,
        agent_selection,
        env_selection,
        fixtures_dir=None,
    ):
        captured["fixtures_dir"] = fixtures_dir
        captured["agent_selection"] = agent_selection
        captured["env_selection"] = env_selection
        return _redteam_result(
            score=12.5,
            score_raw=4.0,
            findings_count=2,
            unique_cells=2,
            agent_selection=agent_selection,
            env_selection=env_selection,
        )

    monkeypatch.setattr(
        test_command,
        "run_redteam_evaluation_with_progress",
        fake_run_redteam_evaluation,
    )

    args = SimpleNamespace(
        submission=str(attack_file),
        budget_s=10.0,
        quick=False,
        name="attack_auto",
        verbose=False,
        track="auto",
        fixtures_dir=str(fixtures_dir),
        agent="deterministic",
    )

    assert test_command.run_test(args) == 0
    saved = json.loads(
        (tmp_path / ".aicomp" / "history" / "attack_auto.json").read_text(encoding="utf-8")
    )
    assert saved["track"] == "redteam"
    assert saved["final_score"] == 12.5
    assert saved["submission_type"] == "attack_only"
    assert saved["env_selection"] == "gym"
    assert captured["fixtures_dir"] == fixtures_dir.resolve()
    assert captured["agent_selection"] == "deterministic"
    assert captured["env_selection"] == "gym"


def test_resolve_track_ignores_comment_mentions_of_other_submission_type(tmp_path: Path) -> None:
    submission = tmp_path / "attack.py"
    submission.write_text(
        '"""Guardrail examples live elsewhere."""\n'
        "# class Guardrail:\n"
        "class AttackAlgorithm:\n"
        "    pass\n",
        encoding="utf-8",
    )

    assert test_command._resolve_track(submission, "auto") == "redteam"


def test_run_test_supports_explicit_dual_track_for_zip(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    submission = tmp_path / "submission.zip"
    fixtures_dir = tmp_path / "fixtures"
    fixtures_dir.mkdir()
    submission.write_bytes(b"zip-placeholder")

    captured: dict[str, object] = {}

    monkeypatch.setattr(
        test_command,
        "_load_track_modules",
        lambda stack, submission_path, track: (object, object),
    )

    def fake_run_dual_evaluation(  # noqa: ANN202
        attack_cls,
        guardrail_cls,
        attack_budget_s,
        defense_budget_s,
        agent_selection,
        env_selection,
        fixtures_dir=None,
    ):
        captured["fixtures_dir"] = fixtures_dir
        captured["agent_selection"] = agent_selection
        captured["env_selection"] = env_selection
        return _dual_result(
            agent_selection=agent_selection,
            env_selection=env_selection,
        )

    monkeypatch.setattr(
        test_command,
        "run_dual_evaluation_with_progress",
        fake_run_dual_evaluation,
    )

    args = SimpleNamespace(
        submission=str(submission),
        budget_s=10.0,
        quick=False,
        name="dual_run",
        verbose=False,
        track="dual",
        fixtures_dir=str(fixtures_dir),
        agent="deterministic",
    )

    assert test_command.run_test(args) == 0
    saved = json.loads(
        (tmp_path / ".aicomp" / "history" / "dual_run.json").read_text(encoding="utf-8")
    )
    assert saved["track"] == "dual"
    assert saved["final_score"] == 810.0
    assert saved["env_selection"] == "sandbox"
    assert captured["fixtures_dir"] == fixtures_dir.resolve()
    assert captured["agent_selection"] == "deterministic"
    assert captured["env_selection"] == "sandbox"


def test_run_test_supports_defense_track_for_guardrail_py(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    guardrail_file = tmp_path / "guardrail.py"
    fixtures_dir = tmp_path / "fixtures"
    fixtures_dir.mkdir()
    guardrail_file.write_text(
        "class Guardrail:\n    pass\n",
        encoding="utf-8",
    )

    captured: dict[str, object] = {}

    monkeypatch.setattr(
        test_command,
        "_load_track_modules",
        lambda stack, submission_path, track: (None, object),
    )

    def fake_run_defense_evaluation(  # noqa: ANN202
        guardrail_cls,
        defense_budget_s,
        agent_selection,
        env_selection,
        fixtures_dir=None,
    ):
        captured["fixtures_dir"] = fixtures_dir
        captured["agent_selection"] = agent_selection
        captured["env_selection"] = env_selection
        return _defense_result(
            agent_selection=agent_selection,
            env_selection=env_selection,
        )

    monkeypatch.setattr(
        test_command,
        "run_defense_evaluation_with_progress",
        fake_run_defense_evaluation,
    )

    args = SimpleNamespace(
        submission=str(guardrail_file),
        budget_s=10.0,
        quick=False,
        name="defense_run",
        verbose=False,
        track="defense",
        fixtures_dir=str(fixtures_dir),
        agent="deterministic",
    )

    assert test_command.run_test(args) == 0
    saved = json.loads(
        (tmp_path / ".aicomp" / "history" / "defense_run.json").read_text(encoding="utf-8")
    )
    assert saved["track"] == "defense"
    assert saved["final_score"] == 900.0
    assert saved["submission_type"] == "guardrail_only"
    assert saved["env_selection"] == "sandbox"
    assert captured["fixtures_dir"] == fixtures_dir.resolve()
    assert captured["agent_selection"] == "deterministic"
    assert captured["env_selection"] == "sandbox"


def test_run_test_allows_explicit_env_override(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    attack_file = tmp_path / "attack.py"
    attack_file.write_text("class AttackAlgorithm:\n    pass\n", encoding="utf-8")

    captured: dict[str, object] = {}

    monkeypatch.setattr(
        test_command,
        "_load_track_modules",
        lambda stack, submission_path, track: (object, None),
    )

    def fake_run_redteam_evaluation(  # noqa: ANN202
        attack_cls,
        attack_budget_s,
        agent_selection,
        env_selection,
        fixtures_dir=None,
    ):
        captured["env_selection"] = env_selection
        return _redteam_result(
            score=1.0,
            score_raw=1.0,
            findings_count=1,
            unique_cells=1,
            agent_selection=agent_selection,
            env_selection=env_selection,
        )

    monkeypatch.setattr(
        test_command,
        "run_redteam_evaluation_with_progress",
        fake_run_redteam_evaluation,
    )

    args = SimpleNamespace(
        submission=str(attack_file),
        budget_s=10.0,
        quick=False,
        name="attack_sandbox",
        verbose=False,
        track="redteam",
        fixtures_dir=None,
        agent="deterministic",
        env="sandbox",
    )

    assert test_command.run_test(args) == 0
    assert captured["env_selection"] == "sandbox"


def test_load_track_modules_only_imports_requested_zip_members(tmp_path: Path, monkeypatch) -> None:
    submission = tmp_path / "submission.zip"
    submission.write_bytes(b"zip-placeholder")
    loaded_members: list[str] = []

    def fake_load_from_zip(zip_path, module_name, file_name):  # noqa: ANN001, ANN202
        loaded_members.append(file_name)
        if file_name == "attack.py":
            return SimpleNamespace(AttackAlgorithm=object), nullcontext()
        return SimpleNamespace(Guardrail=object), nullcontext()

    monkeypatch.setattr(evaluation_core, "load_from_zip", fake_load_from_zip)

    with ExitStack() as stack:
        attack_cls, guardrail_cls = test_command._load_track_modules(
            stack,
            submission,
            "redteam",
        )

    assert attack_cls is object
    assert guardrail_cls is None
    assert loaded_members == ["attack.py"]


def test_run_dual_evaluation_reuses_single_agent_factory(monkeypatch) -> None:
    built_factories: list[object] = []
    attack_factories: list[object] = []
    defense_factories: list[object] = []
    shared_factory = object()

    def fake_build_agent_factory(selection):  # noqa: ANN001, ANN202
        built_factories.append(selection)
        return shared_factory

    def fake_evaluate_attack_once(  # noqa: ANN202
        attack_cls,
        attack_budget_s,
        agent_factory,
        env_selection,
        fixtures_dir=None,
    ):
        attack_factories.append(agent_factory)
        return [], 0.1

    def fake_evaluate_defense_once(  # noqa: ANN202
        guardrail_cls,
        defense_budget_s,
        agent_factory,
        env_selection,
        fixtures_dir=None,
    ):
        defense_factories.append(agent_factory)
        return {"breach_count": 0, "false_positives": 0, "benign_trials": 7}, 0.2

    monkeypatch.setattr(test_command, "build_agent_factory", fake_build_agent_factory)
    monkeypatch.setattr(test_command, "_evaluate_attack_once", fake_evaluate_attack_once)
    monkeypatch.setattr(test_command, "_evaluate_defense_once", fake_evaluate_defense_once)
    monkeypatch.setattr(
        evaluation_core,
        "summarize_attack_findings",
        lambda findings: {
            "score": 10.0,
            "score_raw": 3.0,
            "findings_count": 0,
            "unique_cells": 0,
        },
    )
    monkeypatch.setattr(
        test_command,
        "_build_defense_summary",
        lambda defense_report, elapsed: {
            "score": 800.0,
            "breach_count": 0,
            "false_positives": 0,
            "benign_trials": 7,
            "false_positive_rate": 0.0,
            "time_taken": elapsed,
        },
    )
    monkeypatch.setattr(
        "aicomp_sdk.scoring.get_score_breakdown",
        lambda attack_findings, defense_report: {"attack_mode": "normalized"},
    )

    results = test_command.run_dual_evaluation_with_progress(
        object,
        object,
        5.0,
        5.0,
        AgentSelection.GPT_OSS,
        EnvSelection.SANDBOX,
    )

    assert results["final_score"] == 810.0
    assert built_factories == [AgentSelection.GPT_OSS]
    assert attack_factories == [shared_factory]
    assert defense_factories == [shared_factory]
