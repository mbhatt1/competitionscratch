from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import aicomp_sdk.evaluation.ops as evaluation_ops
from aicomp_sdk.cli.commands import evaluate as evaluate_command
from aicomp_sdk.evaluation.tracks import EvaluationTrack
from aicomp_sdk.hooks import HookRegistry


def test_run_evaluate_resolves_dual_specs_before_submission_import(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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

    def fake_evaluate_dual(*args, **kwargs):  # noqa: ANN001, ANN202
        del args
        kwargs.pop("diagnostics")
        captured["attack_guardrail_spec"] = kwargs["attack_guardrail_spec"]
        captured["defense_hook_spec"] = kwargs["defense_hook_spec"]
        return SimpleNamespace(
            track=EvaluationTrack.DUAL,
            attack=object(),
            defense=object(),
            final_score=1.0,
        )

    monkeypatch.setattr(
        evaluate_command,
        "resolve_attack_guardrail_spec",
        fake_resolve_attack_guardrail_spec,
    )
    monkeypatch.setattr(
        evaluate_command,
        "resolve_defense_hook_spec",
        fake_resolve_defense_hook_spec,
    )
    monkeypatch.setattr(
        evaluate_command,
        "load_track_modules",
        fake_load_track_modules,
    )
    monkeypatch.setattr(
        evaluate_command,
        "evaluate_dual",
        fake_evaluate_dual,
    )
    monkeypatch.setattr(evaluate_command, "_render_summary", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        evaluate_command,
        "build_evaluation_report",
        lambda execution, *, profile: {"final_score": execution.final_score},
    )
    monkeypatch.setattr(
        evaluate_command,
        "_write_outputs",
        lambda **kwargs: None,
    )

    args = SimpleNamespace(
        track="dual",
        submission=str(submission_zip),
        budget_s=10.0,
        fixtures_dir=None,
        artifacts_dir=str(tmp_path / "artifacts"),
        save_transcript=False,
        save_framework_events=False,
        save_agent_debug=False,
        verbosity="summary",
        agent="deterministic",
        env="sandbox",
    )

    assert evaluate_command.run_evaluate(args) == 0
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


def test_run_evaluate_threads_diagnostics_artifacts_and_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attack_file = tmp_path / "attack.py"
    attack_file.write_text("class AttackAlgorithm:\n    pass\n", encoding="utf-8")
    artifacts_dir = tmp_path / "artifacts"
    captured: dict[str, object] = {}

    class FakeRunDiagnostics:
        def __init__(
            self,
            verbosity,
            *,
            transcript_file=None,
            event_log_file=None,
            agent_debug_file=None,
        ):  # noqa: ANN001
            captured["verbosity"] = verbosity
            captured["transcript_file"] = transcript_file
            captured["event_log_file"] = event_log_file
            captured["agent_debug_file"] = agent_debug_file

        def __enter__(self):  # noqa: ANN204
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            return None

    def fake_load_track_modules(stack, submission_path, track):  # noqa: ANN001
        del stack, track
        captured["submission_path"] = submission_path
        return object, None

    def fake_evaluate_redteam(attack_cls, **kwargs):  # noqa: ANN001, ANN202
        del attack_cls
        captured.update(kwargs)
        return SimpleNamespace(
            track=EvaluationTrack.REDTEAM,
            attack=object(),
            defense=None,
            final_score=2.0,
        )

    monkeypatch.setattr(evaluate_command, "RunDiagnostics", FakeRunDiagnostics)
    monkeypatch.setattr(evaluate_command, "load_track_modules", fake_load_track_modules)
    monkeypatch.setattr(evaluate_command, "evaluate_redteam", fake_evaluate_redteam)
    monkeypatch.setattr(evaluate_command, "_render_summary", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        evaluate_command,
        "build_evaluation_report",
        lambda execution, *, profile: {"final_score": execution.final_score},
    )
    monkeypatch.setattr(evaluate_command, "_write_outputs", lambda **kwargs: None)

    args = SimpleNamespace(
        track="redteam",
        submission=str(attack_file),
        budget_s=7.0,
        fixtures_dir=None,
        artifacts_dir=str(artifacts_dir),
        save_transcript=True,
        save_framework_events=True,
        save_agent_debug=True,
        verbosity="debug",
        agent="deterministic",
        env="sandbox",
    )

    assert evaluate_command.run_evaluate(args) == 0
    assert captured["submission_path"] == attack_file.resolve()
    assert captured["budget_s"] == 7.0
    assert captured["transcript_file"] == artifacts_dir.resolve() / "transcript.log"
    assert captured["event_log_file"] == artifacts_dir.resolve() / "framework.jsonl"
    assert captured["agent_debug_file"] == artifacts_dir.resolve() / "agent-debug.jsonl"
    assert captured["diagnostics"] is not None
