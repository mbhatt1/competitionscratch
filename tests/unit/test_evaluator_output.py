from __future__ import annotations

import json
from pathlib import Path

import pytest

from aicomp_sdk.evaluation.diagnostics import (
    EvaluatorVerbosity,
    RunDiagnostics,
    coerce_evaluator_verbosity,
)


def test_coerce_evaluator_verbosity_accepts_strings_and_enums() -> None:
    assert coerce_evaluator_verbosity("debug") is EvaluatorVerbosity.DEBUG
    assert coerce_evaluator_verbosity(EvaluatorVerbosity.PROGRESS) is EvaluatorVerbosity.PROGRESS


def test_capture_stdio_suppresses_output_in_summary_mode(
    capsys: pytest.CaptureFixture[str],
) -> None:
    controller = RunDiagnostics(EvaluatorVerbosity.SUMMARY)

    with controller.capture_stdio("test-run"):
        print("hidden stdout")
        raise_system_stderr("hidden stderr")

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_capture_stdio_routes_output_to_stderr_in_debug_mode(
    capsys: pytest.CaptureFixture[str],
) -> None:
    controller = RunDiagnostics(EvaluatorVerbosity.DEBUG)

    with controller.capture_stdio("test-run"):
        print("debug stdout")
        raise_system_stderr("debug stderr")

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "debug stdout" in captured.err
    assert "debug stderr" in captured.err


def test_capture_stdio_progress_mode_filters_for_useful_go_explore_lines(
    capsys: pytest.CaptureFixture[str],
) -> None:
    controller = RunDiagnostics(EvaluatorVerbosity.PROGRESS)

    with controller.capture_stdio("test-run"):
        print("[GO-EXPLORE] Starting attack run: 5.0s budget, seed=123")
        print("[GO-EXPLORE] *** PREDICATES TRIGGERED: ['DESTRUCTIVE_WRITE'] ***")
        raise_system_stderr("  Findings with predicates: 12")

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "[GO-EXPLORE] Starting attack run" in captured.err
    assert "Findings with predicates: 12" in captured.err
    assert "*** PREDICATES TRIGGERED" not in captured.err


def test_capture_stdio_writes_transcript_file(tmp_path: Path) -> None:
    log_path = tmp_path / "eval.log"
    with RunDiagnostics(EvaluatorVerbosity.SUMMARY, transcript_file=log_path) as controller:
        with controller.capture_stdio("attack run"):
            print("logged stdout")
            raise_system_stderr("logged stderr")

    log_text = log_path.read_text(encoding="utf-8")
    assert "=== attack run ===" in log_text
    assert "logged stdout" in log_text
    assert "logged stderr" in log_text


def test_framework_event_log_stays_separate_from_transcript(tmp_path: Path) -> None:
    transcript_path = tmp_path / "transcript.log"
    event_log_path = tmp_path / "framework.jsonl"

    with RunDiagnostics(
        EvaluatorVerbosity.SUMMARY,
        transcript_file=transcript_path,
        event_log_file=event_log_path,
    ) as controller:
        controller.info(
            "attack_phase_started",
            "Running attack generation and replay...",
            phase="redteam_evaluation",
            kind="phase_start",
            track="redteam",
        )
        with controller.capture_stdio("attack run"):
            print("transcript stdout")
            raise_system_stderr("transcript stderr")

    transcript_text = transcript_path.read_text(encoding="utf-8")
    event_log_lines = event_log_path.read_text(encoding="utf-8").splitlines()
    event_payloads = [json.loads(line) for line in event_log_lines]

    assert "transcript stdout" in transcript_text
    assert "transcript stderr" in transcript_text
    assert "Running attack generation and replay..." not in transcript_text
    assert [payload["message"] for payload in event_payloads] == [
        "Running attack generation and replay..."
    ]
    assert event_payloads[0]["event"] == "attack_phase_started"
    assert event_payloads[0]["phase"] == "redteam_evaluation"
    assert event_payloads[0]["fields"] == {"track": "redteam"}


def test_capture_stdio_adds_failure_note() -> None:
    controller = RunDiagnostics(EvaluatorVerbosity.SUMMARY)

    with pytest.raises(RuntimeError, match="boom") as exc_info:
        with controller.capture_stdio("submission execution"):
            print("before failure")
            raise_system_stderr("stderr before failure")
            raise RuntimeError("boom")

    notes = exc_info.value.__notes__
    assert any("submission execution" in note for note in notes)
    assert any("stdout tail: before failure" in note for note in notes)


def raise_system_stderr(message: str) -> None:
    import sys

    print(message, file=sys.stderr)
