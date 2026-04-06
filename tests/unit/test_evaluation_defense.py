from __future__ import annotations

import json
import sys
from importlib import import_module
from pathlib import Path
from types import ModuleType

import pytest

import aicomp_sdk.evaluation.ops as evaluation_core
import aicomp_sdk.evaluation.submissions as evaluation_submissions
import aicomp_sdk.scoring as scoring
from aicomp_sdk.guardrails.base import Decision, GuardrailBase

# mypy: disable-error-code="unused-ignore,attr-defined"


class _StubGuardrail(GuardrailBase):
    def decide(self, tool_name, tool_args, context) -> Decision:  # type: ignore[no-untyped-def]
        return Decision.allow("stub")


def _stub_guardrail_module() -> ModuleType:
    module = ModuleType("user_guardrail")
    module.Guardrail = _StubGuardrail
    return module


def _artifact_paths(tmp_path: Path) -> tuple[Path, Path, Path]:
    artifacts_dir = tmp_path / "artifacts"
    return artifacts_dir, artifacts_dir / "score.txt", artifacts_dir / "report.json"


def _run_evaluate_cli() -> int:
    sys.argv = [sys.argv[0], "evaluate", *sys.argv[1:]]
    return import_module("aicomp_sdk.cli.main").main()


def test_defense_evaluator_writes_guardrail_only_outputs(tmp_path, monkeypatch) -> None:
    submission = tmp_path / "custom_guardrail_impl.py"
    submission.write_text("class Guardrail:\n    pass\n", encoding="utf-8")
    artifacts_dir, score_path, report_path = _artifact_paths(tmp_path)

    monkeypatch.setattr(
        evaluation_submissions,
        "load_module_from_file",
        lambda submission_path, module_name: _stub_guardrail_module(),
    )

    captured = {}

    def fake_eval_defense(
        guardrail_cls,
        budget_s,
        agent_factory=None,
        env_selection=None,
        guardrail_challenge_env_seed=123,
        benign_seed=999,
        fixtures_dir=None,
        output_controller=None,
        *,
        options=None,
    ):  # type: ignore[no-untyped-def]
        del (
            guardrail_cls,
            guardrail_challenge_env_seed,
            benign_seed,
            fixtures_dir,
            output_controller,
            options,
        )
        captured["budget_s"] = budget_s
        captured["env_selection"] = env_selection
        captured["agent_factory"] = agent_factory
        return {"breach_count": 1, "false_positives": 2, "benign_trials": 7}

    monkeypatch.setattr(evaluation_core, "eval_defense", fake_eval_defense)
    monkeypatch.setattr(scoring, "score_defense", lambda report: 875.0)

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "evaluation.py",
            "defense",
            str(submission),
            "--budget-s",
            "10",
            "--artifacts-dir",
            str(artifacts_dir),
        ],
    )

    _run_evaluate_cli()

    details = json.loads(report_path.read_text(encoding="utf-8"))
    assert float(score_path.read_text(encoding="utf-8").strip()) == 875.0
    assert captured["budget_s"] == 10.0
    assert captured["env_selection"] == "sandbox"
    assert callable(captured["agent_factory"])
    assert details["track"] == "defense"
    assert details["submission_type"] == "guardrail_only"
    assert details["final_score"] == 875.0
    assert details["defense"]["breach_count"] == 1
    assert "attack" not in details


def test_defense_evaluator_requires_guardrail_class(tmp_path, monkeypatch) -> None:
    submission = tmp_path / "guardrail_impl.py"
    submission.write_text("class NotAGuardrail:\n    pass\n", encoding="utf-8")

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "evaluation.py",
            "defense",
            str(submission),
        ],
    )

    with pytest.raises(SystemExit, match="Guardrail"):
        _run_evaluate_cli()
