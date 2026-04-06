from __future__ import annotations

import json
import sys
from importlib import import_module
from pathlib import Path
from types import ModuleType

import pytest

import aicomp_sdk.evaluation.ops as evaluation_core
import aicomp_sdk.evaluation.runner as evaluation_runner
import aicomp_sdk.evaluation.submissions as evaluation_submissions
from aicomp_sdk.agents import build_agent_factory
from aicomp_sdk.agents.debug import AgentDebugEvent
from aicomp_sdk.attacks import AttackAlgorithmBase, AttackCandidate, AttackRunConfig
from aicomp_sdk.cli.commands import evaluate as evaluation
from aicomp_sdk.core.env.api import EnvSelection
from aicomp_sdk.evaluation.budget_policy import DEFAULT_ATTACK_BUDGET_S
from aicomp_sdk.evaluation.ops import eval_attack, summarize_attack_findings
from aicomp_sdk.evaluation.submissions import load_module_from_file

# mypy: disable-error-code="unused-ignore,attr-defined"


ATTACK_SOURCE = """\
from aicomp_sdk import AttackAlgorithmBase, AttackCandidate, AttackRunConfig


class AttackAlgorithm(AttackAlgorithmBase):
    def run(self, env, config: AttackRunConfig) -> list[AttackCandidate]:
        env.reset()
        env.interact("read secret")
        trace = env.export_trace_dict()
        return [AttackCandidate(user_messages=tuple(trace.get("user_messages", [])))]
"""


class _StubAttackAlgorithm(AttackAlgorithmBase):
    def run(self, env, config: AttackRunConfig) -> list[AttackCandidate]:  # type: ignore[no-untyped-def]
        return []


def _stub_attack_module() -> ModuleType:
    module = ModuleType("user_attack")
    module.AttackAlgorithm = _StubAttackAlgorithm
    return module


def _artifact_paths(tmp_path: Path) -> tuple[Path, Path, Path]:
    artifacts_dir = tmp_path / "artifacts"
    return artifacts_dir, artifacts_dir / "score.txt", artifacts_dir / "report.json"


def _empty_attack_summary(findings: object) -> dict[str, float | int]:
    del findings
    return {
        "score": 0.0,
        "score_raw": 0.0,
        "findings_count": 0,
        "unique_cells": 0,
    }


def _run_evaluate_cli() -> int:
    sys.argv = [sys.argv[0], "evaluate", *sys.argv[1:]]
    return import_module("aicomp_sdk.cli.main").main()


def test_redteam_evaluator_writes_attack_only_outputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pytest.importorskip("gymnasium")
    submission = tmp_path / "attack.py"
    submission.write_text(ATTACK_SOURCE, encoding="utf-8")
    artifacts_dir, score_path, report_path = _artifact_paths(tmp_path)

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "evaluation.py",
            "redteam",
            str(submission),
            "--budget-s",
            "1",
            "--artifacts-dir",
            str(artifacts_dir),
            "--agent",
            "deterministic",
        ],
    )

    _run_evaluate_cli()

    score = float(score_path.read_text(encoding="utf-8").strip())
    details = json.loads(report_path.read_text(encoding="utf-8"))

    assert score == details["attack"]["score"]
    assert details["final_score"] == details["attack"]["score"]
    assert details["submission_type"] == "attack_only"
    assert details["env_selection"] == "sandbox"
    assert "defense" not in details


def test_redteam_evaluator_accepts_any_python_filename_with_attackalgorithm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    submission = tmp_path / "custom_attack_impl.py"
    submission.write_text(ATTACK_SOURCE, encoding="utf-8")
    artifacts_dir, _, report_path = _artifact_paths(tmp_path)

    monkeypatch.setattr(
        evaluation_submissions,
        "load_module_from_file",
        lambda submission_path, module_name: _stub_attack_module(),
    )
    monkeypatch.setattr(evaluation_core, "eval_attack", lambda *args, **kwargs: [])
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
            "redteam",
            str(submission),
            "--artifacts-dir",
            str(artifacts_dir),
        ],
    )

    _run_evaluate_cli()

    details = json.loads(report_path.read_text(encoding="utf-8"))
    assert details["track"] == "redteam"
    assert details["submission_type"] == "attack_only"


def test_redteam_evaluator_requires_attackalgorithm_class(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    submission = tmp_path / "attack_impl.py"
    submission.write_text("class NotAnAttack:\n    pass\n", encoding="utf-8")

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "evaluation.py",
            "redteam",
            str(submission),
        ],
    )

    with pytest.raises(SystemExit, match="AttackAlgorithm"):
        _run_evaluate_cli()


def test_evaluator_cli_rejects_legacy_track_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "evaluation.py",
            "--track",
            "redteam",
            "--submission",
            "attack.py",
        ],
    )

    with pytest.raises(SystemExit) as exc_info:
        _run_evaluate_cli()

    assert exc_info.value.code == 2


def test_evaluator_cli_rejects_legacy_output_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "evaluation.py",
            "redteam",
            "attack.py",
            "--out",
            "score.txt",
        ],
    )

    with pytest.raises(SystemExit) as exc_info:
        _run_evaluate_cli()

    assert exc_info.value.code == 2


@pytest.mark.parametrize("budget_s", ["0", "-1", "nan", "inf", "-inf"])
def test_evaluator_cli_rejects_non_positive_budget(
    monkeypatch: pytest.MonkeyPatch,
    budget_s: str,
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "evaluation.py",
            "redteam",
            "attack.py",
            "--budget-s",
            budget_s,
        ],
    )

    with pytest.raises(SystemExit) as exc_info:
        _run_evaluate_cli()

    assert exc_info.value.code == 2


@pytest.mark.parametrize(
    ("legacy_flag", "legacy_value"),
    [
        ("--transcript-file", "eval.debug.log"),
        ("--event-log-file", "eval.events.log"),
        ("--agent-debug-jsonl", "agent.debug.jsonl"),
    ],
)
def test_evaluator_cli_rejects_legacy_diagnostics_path_flags(
    monkeypatch: pytest.MonkeyPatch,
    legacy_flag: str,
    legacy_value: str,
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "evaluation.py",
            "redteam",
            "attack.py",
            legacy_flag,
            legacy_value,
        ],
    )

    with pytest.raises(SystemExit) as exc_info:
        _run_evaluate_cli()

    assert exc_info.value.code == 2


def test_redteam_evaluator_defaults_to_artifacts_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    submission = tmp_path / "attack_impl.py"
    submission.write_text("class AttackAlgorithm:\n    pass\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    monkeypatch.setattr(
        evaluation_submissions,
        "load_module_from_file",
        lambda submission_path, module_name: _stub_attack_module(),
    )
    monkeypatch.setattr(evaluation_core, "eval_attack", lambda *args, **kwargs: [])
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
            "redteam",
            str(submission),
        ],
    )

    _run_evaluate_cli()

    artifacts_dir = tmp_path / evaluation.DEFAULT_ARTIFACTS_DIR_NAME
    assert artifacts_dir.is_dir()
    assert (artifacts_dir / evaluation.SCORE_FILENAME).read_text(encoding="utf-8").strip() == "0.0"
    details = json.loads((artifacts_dir / evaluation.REPORT_FILENAME).read_text(encoding="utf-8"))
    assert details["track"] == "redteam"
    assert not (tmp_path / ".aicomp" / "history").exists()


def test_redteam_score_matches_eval_attack(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("gymnasium")
    submission = tmp_path / "attack.py"
    submission.write_text(ATTACK_SOURCE, encoding="utf-8")
    artifacts_dir, _, report_path = _artifact_paths(tmp_path)

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "evaluation.py",
            "redteam",
            str(submission),
            "--budget-s",
            "1",
            "--artifacts-dir",
            str(artifacts_dir),
            "--agent",
            "deterministic",
        ],
    )
    _run_evaluate_cli()

    attack_mod = load_module_from_file(submission, "comparison_attack")
    findings = eval_attack(
        attack_mod.AttackAlgorithm,
        1.0,
        agent_factory=build_agent_factory("deterministic"),
        env_selection="gym",
    )
    summary = summarize_attack_findings(findings)
    details = json.loads(report_path.read_text(encoding="utf-8"))

    assert details["attack"]["score"] == summary["score"]
    assert details["attack"]["score_raw"] == summary["score_raw"]


def test_redteam_evaluator_passes_fixtures_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    submission = tmp_path / "attack.py"
    submission.write_text("class AttackAlgorithm:\n    pass\n", encoding="utf-8")
    artifacts_dir, _, report_path = _artifact_paths(tmp_path)
    fixtures_dir = tmp_path / "fixtures"
    fixtures_dir.mkdir()

    monkeypatch.setattr(
        evaluation_submissions,
        "load_module_from_file",
        lambda submission_path, module_name: _stub_attack_module(),
    )

    captured = {}

    def fake_eval_attack(
        attack_cls,
        budget_s,
        agent_factory,
        env_selection,
        attack_env_seed=123,
        fixtures_dir=None,
        output_controller=None,
        *,
        options=None,
    ):  # type: ignore[no-untyped-def]
        del attack_cls, attack_env_seed, output_controller, options
        captured["fixtures_dir"] = fixtures_dir
        captured["agent_factory"] = agent_factory
        captured["budget_s"] = budget_s
        captured["env_selection"] = env_selection
        return []

    monkeypatch.setattr(evaluation_core, "eval_attack", fake_eval_attack)
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
            "redteam",
            str(submission),
            "--fixtures-dir",
            str(fixtures_dir),
            "--artifacts-dir",
            str(artifacts_dir),
        ],
    )

    _run_evaluate_cli()

    details = json.loads(report_path.read_text(encoding="utf-8"))
    assert captured["fixtures_dir"] == fixtures_dir.resolve()
    assert callable(captured["agent_factory"])
    assert captured["budget_s"] == DEFAULT_ATTACK_BUDGET_S
    assert captured["env_selection"] is EnvSelection.SANDBOX
    assert details["final_score"] == 0.0
    assert details["track"] == "redteam"


def test_redteam_evaluator_passes_explicit_env_selection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    submission = tmp_path / "attack.py"
    submission.write_text("class AttackAlgorithm:\n    pass\n", encoding="utf-8")
    artifacts_dir, _, _ = _artifact_paths(tmp_path)

    monkeypatch.setattr(
        evaluation_submissions,
        "load_module_from_file",
        lambda submission_path, module_name: _stub_attack_module(),
    )

    captured = {}

    def fake_eval_attack(
        attack_cls,
        budget_s,
        agent_factory,
        env_selection,
        attack_env_seed=123,
        fixtures_dir=None,
        output_controller=None,
        *,
        options=None,
    ):  # type: ignore[no-untyped-def]
        del (
            attack_cls,
            budget_s,
            agent_factory,
            attack_env_seed,
            fixtures_dir,
            output_controller,
            options,
        )
        captured["env_selection"] = env_selection
        return []

    monkeypatch.setattr(evaluation_core, "eval_attack", fake_eval_attack)
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
            "redteam",
            str(submission),
            "--env",
            "sandbox",
            "--artifacts-dir",
            str(artifacts_dir),
        ],
    )

    _run_evaluate_cli()

    assert captured["env_selection"] is EnvSelection.SANDBOX


def test_redteam_default_output_suppresses_eval_noise(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    submission = tmp_path / "attack.py"
    submission.write_text("class AttackAlgorithm:\n    pass\n", encoding="utf-8")
    artifacts_dir, _, _ = _artifact_paths(tmp_path)

    monkeypatch.setattr(
        evaluation_submissions,
        "load_module_from_file",
        lambda submission_path, module_name: _stub_attack_module(),
    )

    def fake_eval_attack(*args, **kwargs):  # type: ignore[no-untyped-def]
        print("noise on stdout")
        print("noise on stderr", file=sys.stderr)
        return []

    monkeypatch.setattr(evaluation_core, "eval_attack", fake_eval_attack)
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
            "redteam",
            str(submission),
            "--artifacts-dir",
            str(artifacts_dir),
        ],
    )

    _run_evaluate_cli()

    captured = capsys.readouterr()
    assert "EVALUATING RED-TEAM SUBMISSION" in captured.out
    assert "FINAL RESULTS" in captured.out
    assert "noise on stdout" not in captured.out
    assert "noise on stdout" not in captured.err
    assert "noise on stderr" not in captured.err


def test_redteam_debug_output_routes_eval_noise_to_stderr_and_transcript(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    submission = tmp_path / "attack.py"
    submission.write_text("class AttackAlgorithm:\n    pass\n", encoding="utf-8")
    artifacts_dir, _, _ = _artifact_paths(tmp_path)
    transcript_path = artifacts_dir / evaluation.TRANSCRIPT_FILENAME

    monkeypatch.setattr(
        evaluation_submissions,
        "load_module_from_file",
        lambda submission_path, module_name: _stub_attack_module(),
    )

    def fake_eval_attack(*args, **kwargs):  # type: ignore[no-untyped-def]
        print("debug stdout")
        print("debug stderr", file=sys.stderr)
        return []

    monkeypatch.setattr(evaluation_core, "eval_attack", fake_eval_attack)
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
            "redteam",
            str(submission),
            "--artifacts-dir",
            str(artifacts_dir),
            "--verbosity",
            "debug",
            "--save-transcript",
        ],
    )

    _run_evaluate_cli()

    captured = capsys.readouterr()
    assert "debug stdout" not in captured.out
    assert "debug stdout" in captured.err
    assert "debug stderr" in captured.err
    transcript_text = transcript_path.read_text(encoding="utf-8")
    assert "debug stdout" in transcript_text
    assert "debug stderr" in transcript_text


def test_redteam_evaluator_writes_optional_diagnostics_into_artifacts_dir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    submission = tmp_path / "attack.py"
    submission.write_text("class AttackAlgorithm:\n    pass\n", encoding="utf-8")
    artifacts_dir, _, _ = _artifact_paths(tmp_path)
    transcript_path = artifacts_dir / evaluation.TRANSCRIPT_FILENAME
    framework_events_path = artifacts_dir / evaluation.FRAMEWORK_EVENTS_FILENAME
    agent_debug_path = artifacts_dir / evaluation.AGENT_DEBUG_FILENAME

    monkeypatch.setattr(
        evaluation_submissions,
        "load_module_from_file",
        lambda submission_path, module_name: _stub_attack_module(),
    )

    def fake_build_agent_factory(agent_selection, *, debug_sink=None):  # type: ignore[no-untyped-def]
        if debug_sink is not None:
            debug_sink.record(
                AgentDebugEvent(
                    backend="deterministic",
                    model=None,
                    phase="request_built",
                    turn_index=1,
                    history_summary={"event_count": 1},
                )
            )
        return lambda: None

    def fake_eval_attack(*args, **kwargs):  # type: ignore[no-untyped-def]
        print("captured stdout")
        print("captured stderr", file=sys.stderr)
        return []

    monkeypatch.setattr(
        evaluation_runner,
        "build_agent_factory",
        fake_build_agent_factory,
    )
    monkeypatch.setattr(evaluation_core, "eval_attack", fake_eval_attack)
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
            "redteam",
            str(submission),
            "--artifacts-dir",
            str(artifacts_dir),
            "--save-transcript",
            "--save-framework-events",
            "--save-agent-debug",
        ],
    )

    _run_evaluate_cli()

    assert transcript_path.is_file()
    assert framework_events_path.is_file()
    assert agent_debug_path.is_file()

    transcript_text = transcript_path.read_text(encoding="utf-8")
    assert "captured stdout" in transcript_text
    assert "captured stderr" in transcript_text

    framework_events = [
        json.loads(line) for line in framework_events_path.read_text(encoding="utf-8").splitlines()
    ]
    assert [event["event"] for event in framework_events] == ["phase_start", "phase_end"]
    assert framework_events[0]["message"] == "Running red-team evaluation..."
    assert framework_events[0]["phase"] == "redteam_evaluation"
    assert framework_events[0]["fields"]["track"] == "redteam"
    assert framework_events[1]["fields"]["score"] == 0.0

    agent_debug_events = [
        json.loads(line) for line in agent_debug_path.read_text(encoding="utf-8").splitlines()
    ]
    assert len(agent_debug_events) == 1
    assert agent_debug_events[0]["phase"] == "request_built"
    assert agent_debug_events[0]["run_id"] == framework_events[0]["run_id"]
