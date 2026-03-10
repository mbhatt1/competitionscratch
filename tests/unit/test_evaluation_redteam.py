from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import evaluation_redteam
from aicomp_sdk.agents import build_agent_factory
from aicomp_sdk.evaluation_core import eval_attack, load_module_from_file, summarize_attack_findings

ATTACK_SOURCE = """\
from aicomp_sdk import AttackAlgorithmBase, AttackCandidate, AttackRunConfig


class AttackAlgorithm(AttackAlgorithmBase):
    def run(self, env, config: AttackRunConfig) -> list[AttackCandidate]:
        env.reset()
        env.interact("read secret")
        trace = env.export_trace_dict()
        return [AttackCandidate(user_messages=tuple(trace.get("user_messages", [])))]
"""


def test_redteam_evaluator_writes_attack_only_outputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    submission = tmp_path / "attack.py"
    submission.write_text(ATTACK_SOURCE, encoding="utf-8")
    out_path = tmp_path / "scores.txt"
    out_json = tmp_path / "scores.json"

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "evaluation_redteam.py",
            "--submission",
            str(submission),
            "--budget-s",
            "1",
            "--out",
            str(out_path),
            "--out_json",
            str(out_json),
            "--agent",
            "deterministic",
        ],
    )

    evaluation_redteam.main()

    score = float(out_path.read_text(encoding="utf-8").strip())
    details = json.loads(out_json.read_text(encoding="utf-8"))

    assert score == details["attack"]["score"]
    assert details["final_score"] == details["attack"]["score"]
    assert details["submission_type"] == "attack_only"
    assert details["env_selection"] == "gym"
    assert "defense" not in details


def test_redteam_evaluator_requires_attack_py_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    submission = tmp_path / "not_attack.py"
    submission.write_text(ATTACK_SOURCE, encoding="utf-8")

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "evaluation_redteam.py",
            "--submission",
            str(submission),
        ],
    )

    with pytest.raises(SystemExit, match="attack.py"):
        evaluation_redteam.main()


def test_redteam_score_matches_eval_attack(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    submission = tmp_path / "attack.py"
    submission.write_text(ATTACK_SOURCE, encoding="utf-8")
    out_path = tmp_path / "scores.txt"
    out_json = tmp_path / "scores.json"

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "evaluation_redteam.py",
            "--submission",
            str(submission),
            "--budget-s",
            "1",
            "--out",
            str(out_path),
            "--out_json",
            str(out_json),
            "--agent",
            "deterministic",
        ],
    )
    evaluation_redteam.main()

    attack_mod = load_module_from_file(submission, "comparison_attack")
    findings = eval_attack(
        attack_mod.AttackAlgorithm,
        1.0,
        agent_factory=build_agent_factory("deterministic"),
        env_selection="gym",
    )
    summary = summarize_attack_findings(findings)
    details = json.loads(out_json.read_text(encoding="utf-8"))

    assert details["attack"]["score"] == summary["score"]
    assert details["attack"]["score_raw"] == summary["score_raw"]


def test_redteam_evaluator_passes_fixtures_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    submission = tmp_path / "attack.py"
    submission.write_text("class AttackAlgorithm:\n    pass\n", encoding="utf-8")
    out_path = tmp_path / "scores.txt"
    out_json = tmp_path / "scores.json"
    fixtures_dir = tmp_path / "fixtures"
    fixtures_dir.mkdir()

    monkeypatch.setattr(
        evaluation_redteam,
        "load_module_from_file",
        lambda submission_path, module_name: SimpleNamespace(AttackAlgorithm=object),
    )

    captured = {}

    def fake_eval_attack(
        attack_cls,
        budget_s,
        agent_factory,
        env_selection,
        attack_seed=123,
        fixtures_dir=None,
    ):  # type: ignore[no-untyped-def]
        captured["fixtures_dir"] = fixtures_dir
        captured["agent_factory"] = agent_factory
        captured["budget_s"] = budget_s
        captured["env_selection"] = env_selection
        return []

    monkeypatch.setattr(evaluation_redteam, "eval_attack", fake_eval_attack)
    monkeypatch.setattr(
        evaluation_redteam,
        "summarize_attack_findings",
        lambda findings: {
            "score": 0.0,
            "score_raw": 0.0,
            "findings_count": 0,
            "unique_cells": 0,
        },
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "evaluation_redteam.py",
            "--submission",
            str(submission),
            "--fixtures_dir",
            str(fixtures_dir),
            "--out",
            str(out_path),
            "--out_json",
            str(out_json),
        ],
    )

    evaluation_redteam.main()

    details = json.loads(out_json.read_text(encoding="utf-8"))
    assert captured["fixtures_dir"] == fixtures_dir.resolve()
    assert callable(captured["agent_factory"])
    assert captured["budget_s"] == evaluation_redteam.DEFAULT_KAGGLE_ATTACK_BUDGET_S
    assert captured["env_selection"] == "gym"
    assert details["final_score"] == 0.0
    assert details["track"] == "redteam"


def test_redteam_evaluator_passes_explicit_env_selection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    submission = tmp_path / "attack.py"
    submission.write_text("class AttackAlgorithm:\n    pass\n", encoding="utf-8")
    out_path = tmp_path / "scores.txt"
    out_json = tmp_path / "scores.json"

    monkeypatch.setattr(
        evaluation_redteam,
        "load_module_from_file",
        lambda submission_path, module_name: SimpleNamespace(AttackAlgorithm=object),
    )

    captured = {}

    def fake_eval_attack(
        attack_cls,
        budget_s,
        agent_factory,
        env_selection,
        attack_seed=123,
        fixtures_dir=None,
    ):  # type: ignore[no-untyped-def]
        captured["env_selection"] = env_selection
        return []

    monkeypatch.setattr(evaluation_redteam, "eval_attack", fake_eval_attack)
    monkeypatch.setattr(
        evaluation_redteam,
        "summarize_attack_findings",
        lambda findings: {
            "score": 0.0,
            "score_raw": 0.0,
            "findings_count": 0,
            "unique_cells": 0,
        },
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "evaluation_redteam.py",
            "--submission",
            str(submission),
            "--env",
            "sandbox",
            "--out",
            str(out_path),
            "--out_json",
            str(out_json),
        ],
    )

    evaluation_redteam.main()

    assert captured["env_selection"] == "sandbox"
