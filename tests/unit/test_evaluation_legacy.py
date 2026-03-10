from __future__ import annotations

import sys
import json
from tempfile import TemporaryDirectory
from types import SimpleNamespace

import evaluation


def test_legacy_evaluator_passes_fixtures_override(tmp_path, monkeypatch) -> None:
    submission_zip = tmp_path / "submission.zip"
    submission_zip.write_bytes(b"placeholder")
    fixtures_dir = tmp_path / "fixtures"
    fixtures_dir.mkdir()
    out_path = tmp_path / "scores.txt"
    out_json = tmp_path / "scores.json"

    def fake_load_from_zip(zip_path, module_name, file_name):  # type: ignore[no-untyped-def]
        tmp = TemporaryDirectory()
        if file_name == "attack.py":
            return SimpleNamespace(AttackAlgorithm=object), tmp
        return SimpleNamespace(Guardrail=object), tmp

    monkeypatch.setattr(evaluation, "load_from_zip", fake_load_from_zip)

    captured = {}

    def fake_eval_attack(
        attack_cls,
        budget_s,
        agent_factory,
        env_selection,
        attack_seed=123,
        fixtures_dir=None,
    ):  # type: ignore[no-untyped-def]
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
    ):  # type: ignore[no-untyped-def]
        captured["defense_fixtures_dir"] = fixtures_dir
        captured["defense_agent_factory"] = agent_factory
        captured["defense_budget_s"] = budget_s
        captured["defense_env_selection"] = env_selection
        return {"breach_count": 0, "false_positives": 0, "benign_trials": 7}

    monkeypatch.setattr(evaluation, "eval_attack", fake_eval_attack)
    monkeypatch.setattr(evaluation, "eval_defense", fake_eval_defense)
    monkeypatch.setattr(evaluation, "score_defense", lambda report: 1000.0)
    monkeypatch.setattr(
        evaluation, "get_score_breakdown", lambda findings, report: {"attack_mode": "normalized"}
    )
    monkeypatch.setattr(
        evaluation,
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
            "evaluation.py",
            "--submission_zip",
            str(submission_zip),
            "--fixtures_dir",
            str(fixtures_dir),
            "--out",
            str(out_path),
            "--out_json",
            str(out_json),
        ],
    )

    evaluation.main()

    assert captured["attack_fixtures_dir"] == fixtures_dir.resolve()
    assert captured["defense_fixtures_dir"] == fixtures_dir.resolve()
    assert callable(captured["attack_agent_factory"])
    assert callable(captured["defense_agent_factory"])
    assert captured["attack_budget_s"] == 1800.0
    assert captured["defense_budget_s"] == 1800.0
    assert captured["attack_env_selection"] == "sandbox"
    assert captured["defense_env_selection"] == "sandbox"
    details = json.loads(out_json.read_text(encoding="utf-8"))
    assert details["env_selection"] == "sandbox"


def test_legacy_evaluator_passes_explicit_env_selection(tmp_path, monkeypatch) -> None:
    submission_zip = tmp_path / "submission.zip"
    submission_zip.write_bytes(b"placeholder")
    out_path = tmp_path / "scores.txt"
    out_json = tmp_path / "scores.json"

    def fake_load_from_zip(zip_path, module_name, file_name):  # type: ignore[no-untyped-def]
        tmp = TemporaryDirectory()
        if file_name == "attack.py":
            return SimpleNamespace(AttackAlgorithm=object), tmp
        return SimpleNamespace(Guardrail=object), tmp

    monkeypatch.setattr(evaluation, "load_from_zip", fake_load_from_zip)

    captured = {}

    def fake_eval_attack(
        attack_cls,
        budget_s,
        agent_factory,
        env_selection,
        attack_seed=123,
        fixtures_dir=None,
    ):  # type: ignore[no-untyped-def]
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
    ):  # type: ignore[no-untyped-def]
        captured["defense_env_selection"] = env_selection
        return {"breach_count": 0, "false_positives": 0, "benign_trials": 7}

    monkeypatch.setattr(evaluation, "eval_attack", fake_eval_attack)
    monkeypatch.setattr(evaluation, "eval_defense", fake_eval_defense)
    monkeypatch.setattr(evaluation, "score_defense", lambda report: 1000.0)
    monkeypatch.setattr(
        evaluation, "get_score_breakdown", lambda findings, report: {"attack_mode": "normalized"}
    )
    monkeypatch.setattr(
        evaluation,
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
            "evaluation.py",
            "--submission_zip",
            str(submission_zip),
            "--env",
            "gym",
            "--out",
            str(out_path),
            "--out_json",
            str(out_json),
        ],
    )

    evaluation.main()

    assert captured["attack_env_selection"] == "gym"
    assert captured["defense_env_selection"] == "gym"
