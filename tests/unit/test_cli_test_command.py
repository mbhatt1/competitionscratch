from __future__ import annotations

import json
from contextlib import ExitStack, nullcontext
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

import aicomp_sdk.evaluation.ops as evaluation_ops
import aicomp_sdk.evaluation.runner as evaluation_runner
import aicomp_sdk.evaluation.submissions as evaluation_submissions
from aicomp_sdk.agents import AgentSelection
from aicomp_sdk.agents.debug import AgentDebugEvent
from aicomp_sdk.cli.commands import test as test_command
from aicomp_sdk.cli.main import create_parser
from aicomp_sdk.core.env.api import EnvSelection
from aicomp_sdk.evaluation.tracks import EvaluationTrack
from aicomp_sdk.hooks import HookRegistry


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
            "evaluated": True,
            "score": score,
            "score_raw": score_raw,
            "findings_count": findings_count,
            "unique_cells": unique_cells,
            "time_taken": 0.1,
        },
        "defense": {
            "evaluated": False,
            "score": None,
            "breach_count": None,
            "false_positives": None,
            "benign_trials": None,
            "false_positive_rate": None,
            "time_taken": None,
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
            "evaluated": True,
            "score": 10.0,
            "score_raw": 3.0,
            "findings_count": 1,
            "unique_cells": 1,
            "time_taken": 0.1,
        },
        "defense": {
            "evaluated": True,
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
        "attack": {
            "evaluated": False,
            "score": None,
            "score_raw": None,
            "findings_count": None,
            "unique_cells": None,
            "time_taken": None,
        },
        "defense": {
            "evaluated": True,
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


def _attack_summary(
    *,
    score: float = 0.0,
    score_raw: float = 0.0,
    findings_count: int = 0,
    unique_cells: int = 0,
) -> dict[str, float | int]:
    return {
        "score": score,
        "score_raw": score_raw,
        "findings_count": findings_count,
        "unique_cells": unique_cells,
    }


def _neutral_defense_report() -> dict[str, int]:
    return {"breach_count": 0, "false_positives": 0, "benign_trials": 7}


def test_run_test_supports_redteam_track_for_attack_py(tmp_path: Path, monkeypatch) -> None:
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
        evaluation_submissions,
        "load_track_modules",
        lambda stack, submission_path, track: (object, None),
    )

    def fake_run_evaluation_with_progress(  # noqa: ANN202
        *,
        track,
        attack_cls,
        guardrail_cls,
        budget_s,
        agent_selection,
        env_selection,
        fixtures_dir=None,
        verbosity=None,
        transcript_file=None,
        event_log_file=None,
        agent_debug_file=None,
        agent_factory=None,
        attack_guardrail_spec=None,
        defense_hook_spec=None,
    ):
        del (
            track,
            attack_cls,
            guardrail_cls,
            agent_debug_file,
            agent_factory,
            verbosity,
            transcript_file,
            event_log_file,
        )
        captured["fixtures_dir"] = fixtures_dir
        captured["agent_selection"] = agent_selection
        captured["env_selection"] = env_selection
        captured["budget_s"] = budget_s
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
        "_run_evaluation_with_progress",
        fake_run_evaluation_with_progress,
    )

    args = SimpleNamespace(
        submission=str(attack_file),
        budget_s=10.0,
        name="attack_auto",
        verbosity=None,
        track="redteam",
        fixtures_dir=str(fixtures_dir),
        agent="deterministic",
        env=None,
        transcript_file=None,
        event_log_file=None,
        agent_debug_jsonl=None,
    )

    assert test_command.run_test(args) == 0
    saved = json.loads(
        (tmp_path / ".aicomp" / "history" / "attack_auto.json").read_text(encoding="utf-8")
    )
    assert saved["track"] == "redteam"
    assert saved["attack"]["evaluated"] is True
    assert saved["defense"]["evaluated"] is False
    assert saved["defense"]["score"] is None
    assert saved["final_score"] == 12.5
    assert saved["submission_type"] == "attack_only"
    assert saved["env_selection"] == "sandbox"
    assert captured["fixtures_dir"] == fixtures_dir.resolve()
    assert captured["agent_selection"] == "deterministic"
    assert captured["env_selection"] == "sandbox"
    assert captured["budget_s"] == 10.0


def test_run_test_supports_explicit_dual_track_for_zip(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    submission = tmp_path / "submission.zip"
    fixtures_dir = tmp_path / "fixtures"
    fixtures_dir.mkdir()
    submission.write_bytes(b"zip-placeholder")

    captured: dict[str, object] = {}

    monkeypatch.setattr(
        evaluation_submissions,
        "load_track_modules",
        lambda stack, submission_path, track: (object, object),
    )

    def fake_run_evaluation_with_progress(  # noqa: ANN202
        *,
        track,
        attack_cls,
        guardrail_cls,
        budget_s,
        agent_selection,
        env_selection,
        fixtures_dir=None,
        verbosity=None,
        transcript_file=None,
        event_log_file=None,
        agent_debug_file=None,
        agent_factory=None,
        attack_guardrail_spec=None,
        defense_hook_spec=None,
    ):
        del (
            track,
            attack_cls,
            guardrail_cls,
            agent_debug_file,
            agent_factory,
            verbosity,
            transcript_file,
            event_log_file,
        )
        captured["fixtures_dir"] = fixtures_dir
        captured["agent_selection"] = agent_selection
        captured["env_selection"] = env_selection
        captured["budget_s"] = budget_s
        return _dual_result(
            agent_selection=agent_selection,
            env_selection=env_selection,
        )

    monkeypatch.setattr(
        test_command,
        "_run_evaluation_with_progress",
        fake_run_evaluation_with_progress,
    )

    args = SimpleNamespace(
        submission=str(submission),
        budget_s=10.0,
        name="dual_run",
        verbosity=None,
        track="dual",
        fixtures_dir=str(fixtures_dir),
        agent="deterministic",
        env=None,
        transcript_file=None,
        event_log_file=None,
        agent_debug_jsonl=None,
    )

    assert test_command.run_test(args) == 0
    saved = json.loads(
        (tmp_path / ".aicomp" / "history" / "dual_run.json").read_text(encoding="utf-8")
    )
    assert saved["track"] == "dual"
    assert saved["attack"]["evaluated"] is True
    assert saved["defense"]["evaluated"] is True
    assert saved["final_score"] == 810.0
    assert saved["env_selection"] == "sandbox"
    assert captured["fixtures_dir"] == fixtures_dir.resolve()
    assert captured["agent_selection"] == "deterministic"
    assert captured["env_selection"] == "sandbox"
    assert captured["budget_s"] == 10.0


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
        evaluation_submissions,
        "load_track_modules",
        lambda stack, submission_path, track: (None, object),
    )

    def fake_run_evaluation_with_progress(  # noqa: ANN202
        *,
        track,
        attack_cls,
        guardrail_cls,
        budget_s,
        agent_selection,
        env_selection,
        fixtures_dir=None,
        verbosity=None,
        transcript_file=None,
        event_log_file=None,
        agent_debug_file=None,
        agent_factory=None,
        attack_guardrail_spec=None,
        defense_hook_spec=None,
    ):
        del (
            track,
            attack_cls,
            guardrail_cls,
            agent_debug_file,
            agent_factory,
            verbosity,
            transcript_file,
            event_log_file,
        )
        captured["fixtures_dir"] = fixtures_dir
        captured["agent_selection"] = agent_selection
        captured["env_selection"] = env_selection
        captured["budget_s"] = budget_s
        return _defense_result(
            agent_selection=agent_selection,
            env_selection=env_selection,
        )

    monkeypatch.setattr(
        test_command,
        "_run_evaluation_with_progress",
        fake_run_evaluation_with_progress,
    )

    args = SimpleNamespace(
        submission=str(guardrail_file),
        budget_s=10.0,
        name="defense_run",
        verbosity=None,
        track="defense",
        fixtures_dir=str(fixtures_dir),
        agent="deterministic",
        env=None,
        transcript_file=None,
        event_log_file=None,
        agent_debug_jsonl=None,
    )

    assert test_command.run_test(args) == 0
    saved = json.loads(
        (tmp_path / ".aicomp" / "history" / "defense_run.json").read_text(encoding="utf-8")
    )
    assert saved["track"] == "defense"
    assert saved["attack"]["evaluated"] is False
    assert saved["attack"]["score"] is None
    assert saved["defense"]["evaluated"] is True
    assert saved["final_score"] == 900.0
    assert saved["submission_type"] == "guardrail_only"
    assert saved["env_selection"] == "sandbox"
    assert captured["fixtures_dir"] == fixtures_dir.resolve()
    assert captured["agent_selection"] == "deterministic"
    assert captured["env_selection"] == "sandbox"
    assert captured["budget_s"] == 10.0


def test_run_test_allows_explicit_env_override(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    attack_file = tmp_path / "attack.py"
    attack_file.write_text("class AttackAlgorithm:\n    pass\n", encoding="utf-8")

    captured: dict[str, object] = {}

    monkeypatch.setattr(
        evaluation_submissions,
        "load_track_modules",
        lambda stack, submission_path, track: (object, None),
    )

    def fake_run_evaluation_with_progress(  # noqa: ANN202
        *,
        track,
        attack_cls,
        guardrail_cls,
        budget_s,
        agent_selection,
        env_selection,
        fixtures_dir=None,
        verbosity=None,
        transcript_file=None,
        event_log_file=None,
        agent_debug_file=None,
        agent_factory=None,
        attack_guardrail_spec=None,
        defense_hook_spec=None,
    ):
        del (
            track,
            attack_cls,
            guardrail_cls,
            budget_s,
            agent_debug_file,
            agent_factory,
            verbosity,
            transcript_file,
            event_log_file,
            fixtures_dir,
        )
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
        "_run_evaluation_with_progress",
        fake_run_evaluation_with_progress,
    )

    args = SimpleNamespace(
        submission=str(attack_file),
        budget_s=10.0,
        name="attack_sandbox",
        verbosity=None,
        track="redteam",
        fixtures_dir=None,
        agent="deterministic",
        env="sandbox",
        transcript_file=None,
        event_log_file=None,
        agent_debug_jsonl=None,
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

    monkeypatch.setattr(evaluation_submissions, "load_from_zip", fake_load_from_zip)

    with ExitStack() as stack:
        attack_cls, guardrail_cls = evaluation_submissions.load_track_modules(
            stack,
            submission,
            EvaluationTrack.REDTEAM,
        )

    assert attack_cls is object
    assert guardrail_cls is None
    assert loaded_members == ["attack.py"]


def test_run_dual_evaluation_reuses_single_agent_factory(monkeypatch) -> None:
    built_factories: list[object] = []
    attack_factories: list[object] = []
    defense_factories: list[object] = []
    shared_factory = object()

    def fake_build_agent_factory(selection, debug_sink=None):  # noqa: ANN001, ANN202
        built_factories.append((selection, debug_sink))
        return shared_factory

    def fake_eval_attack(  # noqa: ANN202
        attack_cls,
        attack_budget_s,
        agent_factory,
        env_selection,
        fixtures_dir=None,
        output_controller=None,
        *,
        options=None,
    ):
        del options, output_controller, attack_cls, attack_budget_s, env_selection, fixtures_dir
        attack_factories.append(agent_factory)
        return []

    def fake_eval_defense(  # noqa: ANN202
        guardrail_cls,
        defense_budget_s,
        agent_factory,
        env_selection,
        fixtures_dir=None,
        output_controller=None,
        *,
        options=None,
    ):
        del options, output_controller, guardrail_cls, defense_budget_s, env_selection, fixtures_dir
        defense_factories.append(agent_factory)
        return _neutral_defense_report()

    monkeypatch.setattr(evaluation_runner, "build_agent_factory", fake_build_agent_factory)
    monkeypatch.setattr(evaluation_ops, "eval_attack", fake_eval_attack)
    monkeypatch.setattr(evaluation_ops, "eval_defense", fake_eval_defense)
    monkeypatch.setattr(
        evaluation_ops,
        "summarize_attack_findings",
        lambda findings: _attack_summary(score=10.0, score_raw=3.0),
    )
    monkeypatch.setattr("aicomp_sdk.scoring.score_defense", lambda report: 800.0)
    monkeypatch.setattr(
        "aicomp_sdk.scoring.get_score_breakdown",
        lambda attack_findings, defense_report: {"attack_mode": "normalized"},
    )

    results = test_command.run_dual_evaluation_with_progress(
        object,
        object,
        10.0,
        AgentSelection.GPT_OSS,
        EnvSelection.SANDBOX,
        verbosity=test_command.EvaluatorVerbosity.SUMMARY,
    )

    assert results["final_score"] == 810.0
    assert results["attack"]["evaluated"] is True
    assert results["defense"]["evaluated"] is True
    assert built_factories == [(AgentSelection.GPT_OSS, None)]
    assert attack_factories == [shared_factory]
    assert defense_factories == [shared_factory]


def test_create_parser_accepts_agent_debug_jsonl() -> None:
    parser = create_parser()

    args = parser.parse_args(
        [
            "test",
            "redteam",
            "attack.py",
            "--agent",
            "openai",
            "--agent-debug-jsonl",
            "/tmp/agent-debug.jsonl",
            "--verbosity",
            "debug",
            "--transcript-file",
            "/tmp/evaluator-transcript.log",
            "--event-log-file",
            "/tmp/evaluator-events.log",
        ]
    )

    assert args.agent is AgentSelection.OPENAI
    assert args.agent_debug_jsonl == "/tmp/agent-debug.jsonl"
    assert args.verbosity is test_command.EvaluatorVerbosity.DEBUG
    assert args.transcript_file == "/tmp/evaluator-transcript.log"
    assert args.event_log_file == "/tmp/evaluator-events.log"


def test_create_parser_accepts_evaluate_redteam_command() -> None:
    parser = create_parser()

    args = parser.parse_args(["evaluate", "redteam", "attack.py", "--verbosity", "debug"])

    assert args.command == "evaluate"
    assert args.track == "redteam"
    assert args.submission == "attack.py"
    assert args.verbosity is test_command.EvaluatorVerbosity.DEBUG


def test_create_parser_coerces_env_selection() -> None:
    parser = create_parser()

    args = parser.parse_args(["test", "redteam", "attack.py", "--env", "gym"])

    assert args.env is EnvSelection.GYM


def test_create_parser_uses_named_cli_budget_default() -> None:
    parser = create_parser()

    args = parser.parse_args(["test", "redteam", "attack.py"])

    assert args.budget_s is None
    assert args.verbosity is test_command.EvaluatorVerbosity.SUMMARY


def test_create_parser_explains_when_to_use_evaluate_vs_test() -> None:
    parser = create_parser()

    help_text = parser.format_help()

    assert "Use `aicomp evaluate` for scorer-style runs" in help_text
    assert "Use `aicomp test` for local iteration" in help_text


@pytest.mark.parametrize("budget_s", ["0", "-1", "nan", "inf", "-inf"])
def test_create_parser_rejects_invalid_test_budgets(budget_s: str) -> None:
    parser = create_parser()

    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["test", "redteam", "attack.py", "--budget-s", budget_s])

    assert exc_info.value.code == 2


def test_create_parser_rejects_legacy_track_flag_shape() -> None:
    parser = create_parser()

    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["test", "attack.py", "--track", "redteam"])

    assert exc_info.value.code == 2


def test_resolve_agent_factory_threads_jsonl_debug_sink(monkeypatch, tmp_path: Path) -> None:
    captured: dict[str, object] = {}

    def fake_build_agent_factory(selection, debug_sink=None):  # noqa: ANN001, ANN202
        captured["selection"] = selection
        captured["debug_sink"] = debug_sink
        return object()

    monkeypatch.setattr(evaluation_runner, "build_agent_factory", fake_build_agent_factory)
    debug_path = tmp_path / "agent-debug.jsonl"

    with test_command.RunDiagnostics(
        test_command.EvaluatorVerbosity.SUMMARY,
        agent_debug_file=debug_path,
    ) as diagnostics:
        factory, resolved_agent = evaluation_runner.resolve_agent_factory(
            agent_selection=AgentSelection.OPENAI,
            diagnostics=diagnostics,
        )

    assert factory is not None
    assert resolved_agent == evaluation_runner.ResolvedAgentConfig(
        selection=AgentSelection.OPENAI,
        label="openai",
    )
    assert captured["selection"] is AgentSelection.OPENAI
    debug_sink = captured["debug_sink"]
    assert debug_sink is not None
    debug_sink.record(
        AgentDebugEvent(
            backend="openai_responses",
            model="gpt-4o-mini",
            phase="request_built",
            turn_index=1,
            history_summary={"event_count": 1},
        )
    )
    payload = json.loads(debug_path.read_text(encoding="utf-8").splitlines()[0])
    assert payload["phase"] == "request_built"


def test_run_test_threads_agent_debug_jsonl_to_redteam_eval(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    attack_file = tmp_path / "attack.py"
    debug_path = tmp_path / "logs" / "agent-debug.jsonl"
    attack_file.write_text("class AttackAlgorithm:\n    pass\n", encoding="utf-8")
    captured: dict[str, object] = {}

    monkeypatch.setattr(
        evaluation_submissions,
        "load_track_modules",
        lambda stack, submission_path, track: (object, None),
    )

    def fake_run_evaluation_with_progress(  # noqa: ANN202
        *,
        track,
        attack_cls,
        guardrail_cls,
        budget_s,
        agent_selection,
        env_selection,
        fixtures_dir=None,
        verbosity=None,
        transcript_file=None,
        event_log_file=None,
        agent_debug_file=None,
        agent_factory=None,
        attack_guardrail_spec=None,
        defense_hook_spec=None,
    ):
        del (
            track,
            attack_cls,
            guardrail_cls,
            budget_s,
            agent_selection,
            env_selection,
            fixtures_dir,
            agent_factory,
        )
        captured["agent_debug_file"] = agent_debug_file
        captured["verbosity"] = verbosity
        captured["transcript_file"] = transcript_file
        captured["event_log_file"] = event_log_file
        return _redteam_result(
            score=1.0,
            score_raw=1.0,
            findings_count=1,
            unique_cells=1,
            agent_selection="openai",
            env_selection="sandbox",
        )

    monkeypatch.setattr(
        test_command,
        "_run_evaluation_with_progress",
        fake_run_evaluation_with_progress,
    )

    args = SimpleNamespace(
        submission=str(attack_file),
        budget_s=10.0,
        name="attack_debug",
        verbosity="debug",
        track="redteam",
        fixtures_dir=None,
        agent="openai",
        env=None,
        transcript_file=str(tmp_path / "logs" / "evaluator-transcript.log"),
        event_log_file=str(tmp_path / "logs" / "evaluator-events.log"),
        agent_debug_jsonl=str(debug_path),
    )

    assert test_command.run_test(args) == 0
    assert captured["agent_debug_file"] == debug_path.resolve()
    assert captured["verbosity"] is test_command.EvaluatorVerbosity.DEBUG
    assert captured["transcript_file"] == (tmp_path / "logs" / "evaluator-transcript.log").resolve()
    assert captured["event_log_file"] == (tmp_path / "logs" / "evaluator-events.log").resolve()


def test_run_redteam_evaluation_allows_diagnostics_debug_file_with_custom_agent_factory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    debug_path = tmp_path / "logs" / "agent-debug.jsonl"

    monkeypatch.setattr(evaluation_ops, "eval_attack", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        evaluation_ops,
        "summarize_attack_findings",
        lambda findings: _attack_summary(),
    )

    results = test_command.run_redteam_evaluation_with_progress(
        object,
        5.0,
        AgentSelection.AUTO,
        EnvSelection.SANDBOX,
        agent_debug_file=debug_path,
        agent_factory=lambda: object(),
    )

    assert results["track"] == "redteam"


def test_run_test_resolves_dual_specs_before_submission_import(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    submission_zip = tmp_path / "submission.zip"
    submission_zip.write_bytes(b"fake-zip")
    events: list[str] = []
    captured: dict[str, object] = {}

    def fake_resolve_attack_guardrail_spec() -> evaluation_ops.AttackGuardrailSpec:
        events.append("resolve_guardrail")
        return evaluation_ops.AttackGuardrailSpec(
            id="pre_resolved_guardrail",
            version="1",
            guardrail_factory=object,
        )

    def fake_resolve_defense_hook_spec() -> evaluation_ops.DefenseHookSpec:
        events.append("resolve_hooks")
        return evaluation_ops.DefenseHookSpec(
            id="pre_resolved_hooks",
            version="1",
            hook_registry_factory=HookRegistry,
        )

    def fake_load_track_modules(stack, submission_path, track):  # noqa: ANN001
        del stack, submission_path, track
        events.append("load_submission")
        return object, object

    def fake_run_evaluation_with_progress(  # noqa: ANN202
        *,
        track,
        attack_cls,
        guardrail_cls,
        budget_s,
        agent_selection,
        env_selection,
        fixtures_dir=None,
        verbosity=None,
        transcript_file=None,
        event_log_file=None,
        agent_debug_file=None,
        agent_factory=None,
        attack_guardrail_spec=None,
        defense_hook_spec=None,
    ):
        del (
            track,
            attack_cls,
            guardrail_cls,
            budget_s,
            agent_selection,
            env_selection,
            fixtures_dir,
            verbosity,
            transcript_file,
            event_log_file,
            agent_debug_file,
            agent_factory,
        )
        captured["attack_guardrail_spec"] = attack_guardrail_spec
        captured["defense_hook_spec"] = defense_hook_spec
        return _redteam_result(
            score=1.0,
            score_raw=1.0,
            findings_count=1,
            unique_cells=1,
            agent_selection="deterministic",
            env_selection="sandbox",
        )

    monkeypatch.setattr(
        test_command,
        "resolve_attack_guardrail_spec",
        fake_resolve_attack_guardrail_spec,
    )
    monkeypatch.setattr(
        test_command,
        "resolve_defense_hook_spec",
        fake_resolve_defense_hook_spec,
    )
    monkeypatch.setattr(
        evaluation_submissions,
        "load_track_modules",
        fake_load_track_modules,
    )
    monkeypatch.setattr(
        test_command,
        "_run_evaluation_with_progress",
        fake_run_evaluation_with_progress,
    )

    args = SimpleNamespace(
        submission=str(submission_zip),
        budget_s=10.0,
        name="pre_resolved_specs",
        verbosity=None,
        track="dual",
        fixtures_dir=None,
        agent="deterministic",
        env=None,
        transcript_file=None,
        event_log_file=None,
        agent_debug_jsonl=None,
    )

    assert test_command.run_test(args) == 0
    assert events == ["resolve_guardrail", "resolve_hooks", "load_submission"]
    assert captured["attack_guardrail_spec"] == evaluation_ops.AttackGuardrailSpec(
        id="pre_resolved_guardrail",
        version="1",
        guardrail_factory=object,
    )
    assert captured["defense_hook_spec"] == evaluation_ops.DefenseHookSpec(
        id="pre_resolved_hooks",
        version="1",
        hook_registry_factory=HookRegistry,
    )


def test_run_redteam_evaluation_threads_output_controller(monkeypatch, tmp_path: Path) -> None:
    captured: dict[str, object] = {}

    class FakeRunDiagnostics:
        def __init__(
            self,
            verbosity,
            *,
            transcript_file=None,
            event_log_file=None,
            agent_debug_file=None,
            stderr=None,
        ):  # noqa: ANN001
            del stderr
            captured["verbosity"] = verbosity
            captured["transcript_file"] = transcript_file
            captured["event_log_file"] = event_log_file
            captured["agent_debug_file"] = agent_debug_file
            self.run_id = "test-run-id"

        def __enter__(self):  # noqa: ANN204
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            return None

        def capture_stdio(self, label: str):  # noqa: ANN201
            captured["label"] = label
            return nullcontext()

        def phase(self, name: str):  # noqa: ANN201
            captured["phase_scope"] = name
            return self

        def make_agent_debug_sink(self):  # noqa: ANN201
            return None

        def record_event(  # noqa: ANN201, ANN001
            self,
            *,
            level,
            event,
            message,
            phase,
            kind,
            fields=None,
            render=True,
        ):
            events = cast(list[dict[str, object]], captured.setdefault("events", []))
            events.append(
                {
                    "level": level,
                    "event": event,
                    "message": message,
                    "phase": phase,
                    "kind": kind,
                    "fields": fields,
                    "render": render,
                }
            )

    def fake_eval_attack(  # noqa: ANN202
        attack_cls,
        attack_budget_s,
        agent_factory,
        env_selection,
        fixtures_dir=None,
        output_controller=None,
        *,
        options=None,
    ):
        del options, attack_cls, attack_budget_s, agent_factory, env_selection, fixtures_dir
        captured["output_controller"] = output_controller
        return []

    monkeypatch.setattr(test_command, "RunDiagnostics", FakeRunDiagnostics)
    monkeypatch.setattr(evaluation_ops, "eval_attack", fake_eval_attack)
    monkeypatch.setattr(
        evaluation_ops,
        "summarize_attack_findings",
        lambda findings: _attack_summary(),
    )

    transcript_file = tmp_path / "evaluator-transcript.log"
    event_log_file = tmp_path / "evaluator-events.log"
    results = test_command.run_redteam_evaluation_with_progress(
        object,
        5.0,
        AgentSelection.DETERMINISTIC,
        EnvSelection.GYM,
        verbosity=test_command.EvaluatorVerbosity.PROGRESS,
        transcript_file=transcript_file,
        event_log_file=event_log_file,
    )

    assert results["track"] == "redteam"
    assert captured["verbosity"] is test_command.EvaluatorVerbosity.PROGRESS
    assert captured["transcript_file"] == transcript_file
    assert captured["event_log_file"] == event_log_file
    assert captured["label"] == "red-team evaluation"
    assert captured["output_controller"] is not None
    events = cast(list[dict[str, object]], captured["events"])
    assert events[0]["phase"] == "redteam_evaluation"
    assert events[0]["render"] is False


def test_run_redteam_evaluation_writes_framework_events_for_quiet_runs(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        evaluation_runner,
        "resolve_agent_factory",
        lambda *args, **kwargs: (
            object(),
            evaluation_runner.ResolvedAgentConfig(selection=None, label="custom"),
        ),
    )
    monkeypatch.setattr(evaluation_ops, "eval_attack", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        evaluation_ops,
        "summarize_attack_findings",
        lambda findings: _attack_summary(),
    )

    event_log_file = tmp_path / "evaluator-events.log"
    results = test_command.run_redteam_evaluation_with_progress(
        object,
        5.0,
        AgentSelection.DETERMINISTIC,
        EnvSelection.GYM,
        verbosity=test_command.EvaluatorVerbosity.SUMMARY,
        event_log_file=event_log_file,
    )

    assert results["track"] == "redteam"
    event_payloads = [
        json.loads(line) for line in event_log_file.read_text(encoding="utf-8").splitlines()
    ]
    assert [payload["message"] for payload in event_payloads] == [
        "Running red-team evaluation...",
        "Red-team evaluation complete.",
    ]
