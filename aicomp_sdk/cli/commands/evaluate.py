"""Evaluator subcommand implementation."""

from __future__ import annotations

import argparse
import json
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, cast

from aicomp_sdk.cli.commands.options import add_shared_execution_arguments
from aicomp_sdk.evaluation.budget_policy import (
    resolve_standalone_budget_plan as _resolve_budget_plan,
)
from aicomp_sdk.evaluation.diagnostics import EvaluatorVerbosity, RunDiagnostics
from aicomp_sdk.evaluation.ops import (
    resolve_attack_guardrail_spec,
    resolve_defense_hook_spec,
)
from aicomp_sdk.evaluation.reports import ReportProfile, build_evaluation_report
from aicomp_sdk.evaluation.runner import (
    AttackExecution,
    DefenseExecution,
    EvaluationExecution,
    evaluate_defense,
    evaluate_dual,
    evaluate_redteam,
)
from aicomp_sdk.evaluation.submissions import load_track_modules
from aicomp_sdk.evaluation.tracks import EvaluationTrack


@dataclass(frozen=True, slots=True)
class RedteamSubmission:
    path: Path


@dataclass(frozen=True, slots=True)
class DefenseSubmission:
    path: Path


@dataclass(frozen=True, slots=True)
class DualSubmission:
    path: Path


SubmissionSpec = RedteamSubmission | DefenseSubmission | DualSubmission
DEFAULT_ARTIFACTS_DIR_NAME: Final[str] = "evaluation_artifacts"
SCORE_FILENAME: Final[str] = "score.txt"
REPORT_FILENAME: Final[str] = "report.json"
TRANSCRIPT_FILENAME: Final[str] = "transcript.log"
FRAMEWORK_EVENTS_FILENAME: Final[str] = "framework.jsonl"
AGENT_DEBUG_FILENAME: Final[str] = "agent-debug.jsonl"


def _require_attack(execution: EvaluationExecution) -> AttackExecution:
    attack = execution.attack
    if attack is None:
        raise RuntimeError(f"{execution.track.value} execution missing attack results")
    return attack


def _require_defense(execution: EvaluationExecution) -> DefenseExecution:
    defense = execution.defense
    if defense is None:
        raise RuntimeError(f"{execution.track.value} execution missing defense results")
    return defense


@dataclass(frozen=True, slots=True)
class EvaluatorArtifacts:
    dir_path: Path
    score_path: Path
    report_path: Path
    transcript_path: Path
    framework_events_path: Path
    agent_debug_path: Path


def _add_common_arguments(parser: argparse.ArgumentParser) -> None:
    add_shared_execution_arguments(
        parser,
        budget_default=None,
        budget_help=(
            "Total evaluation budget in seconds. Defaults to 1800 for redteam/defense "
            "and 3600 for dual."
        ),
        agent_help="Agent selection mode for evaluation runs.",
        env_help=(
            "Evaluation environment selection. Defaults to sandbox; pass --env gym explicitly "
            "when needed."
        ),
        fixtures_help="Optional fixtures root override for the selected track.",
        verbosity_help="Control evaluator diagnostic output (summary, progress, debug).",
    )
    parser.add_argument(
        "--artifacts-dir",
        type=str,
        default=DEFAULT_ARTIFACTS_DIR_NAME,
        help="Directory for evaluator-owned machine-readable artifacts.",
    )
    parser.add_argument(
        "--save-transcript",
        action="store_true",
        help="Write raw captured stdout/stderr to transcript.log under --artifacts-dir.",
    )
    parser.add_argument(
        "--save-framework-events",
        action="store_true",
        help="Write structured framework events to framework.jsonl under --artifacts-dir.",
    )
    parser.add_argument(
        "--save-agent-debug",
        action="store_true",
        help=(
            "Write raw agent backend debug events to agent-debug.jsonl under "
            "--artifacts-dir. Keep this artifact local."
        ),
    )


def _add_track_subparsers(parser: argparse.ArgumentParser) -> None:
    common = argparse.ArgumentParser(add_help=False)
    _add_common_arguments(common)

    subparsers = parser.add_subparsers(dest="track", required=True)

    redteam_parser = subparsers.add_parser(
        EvaluationTrack.REDTEAM.value,
        parents=[common],
        help="Evaluate a Python attack module that defines AttackAlgorithm.",
    )
    redteam_parser.add_argument(
        "submission",
        metavar="ATTACK_MODULE",
        help="Path to a Python file that defines AttackAlgorithm.",
    )

    defense_parser = subparsers.add_parser(
        EvaluationTrack.DEFENSE.value,
        parents=[common],
        help="Evaluate a Python guardrail module that defines Guardrail.",
    )
    defense_parser.add_argument(
        "submission",
        metavar="GUARDRAIL_MODULE",
        help="Path to a Python file that defines Guardrail.",
    )

    dual_parser = subparsers.add_parser(
        EvaluationTrack.DUAL.value,
        parents=[common],
        help="Evaluate a submission zip containing attack.py and guardrail.py.",
    )
    dual_parser.add_argument(
        "submission",
        metavar="SUBMISSION_ZIP",
        help="Path to a submission zip containing attack.py and guardrail.py.",
    )


def add_evaluate_parser(
    subparsers: argparse._SubParsersAction,
) -> argparse.ArgumentParser:
    parser = cast(
        argparse.ArgumentParser,
        subparsers.add_parser(
            "evaluate",
            help="Run scorer-style evaluation and write artifacts",
            description="Evaluate red-team, defense, or dual-track submissions.",
        ),
    )
    _add_track_subparsers(parser)
    return parser


def _resolve_submission_path(raw_path: str) -> Path:
    submission_path = Path(raw_path).expanduser().resolve()
    if not submission_path.exists():
        raise SystemExit(f"Submission not found: {submission_path}")
    return submission_path


def _build_submission_spec(track: EvaluationTrack, raw_path: str) -> SubmissionSpec:
    submission_path = _resolve_submission_path(raw_path)
    if track is EvaluationTrack.REDTEAM:
        return RedteamSubmission(submission_path)
    if track is EvaluationTrack.DEFENSE:
        return DefenseSubmission(submission_path)
    return DualSubmission(submission_path)


def _resolve_artifacts(raw_dir: str | None) -> EvaluatorArtifacts:
    artifacts_dir = Path(raw_dir or DEFAULT_ARTIFACTS_DIR_NAME).expanduser().resolve()
    return EvaluatorArtifacts(
        dir_path=artifacts_dir,
        score_path=artifacts_dir / SCORE_FILENAME,
        report_path=artifacts_dir / REPORT_FILENAME,
        transcript_path=artifacts_dir / TRANSCRIPT_FILENAME,
        framework_events_path=artifacts_dir / FRAMEWORK_EVENTS_FILENAME,
        agent_debug_path=artifacts_dir / AGENT_DEBUG_FILENAME,
    )


def _write_outputs(
    *,
    artifacts: EvaluatorArtifacts,
    final_score: float,
    details: dict[str, Any],
    transcript_file: Path | None = None,
    framework_events_file: Path | None = None,
    agent_debug_file: Path | None = None,
) -> None:
    artifacts.dir_path.mkdir(parents=True, exist_ok=True)
    artifacts.score_path.write_text(f"{final_score}\n", encoding="utf-8")
    artifacts.report_path.write_text(json.dumps(details, indent=2), encoding="utf-8")
    print(f"\nArtifacts written to: {artifacts.dir_path}", flush=True)
    print(f"Score written to: {artifacts.score_path}", flush=True)
    print(f"Report written to: {artifacts.report_path}", flush=True)
    if transcript_file is not None:
        print(f"Transcript written to: {transcript_file}", flush=True)
    if framework_events_file is not None:
        print(f"Framework events written to: {framework_events_file}", flush=True)
    if agent_debug_file is not None:
        print(f"Agent debug JSONL written to: {agent_debug_file}", flush=True)


def _render_summary(
    execution: EvaluationExecution,
    *,
    verbosity: EvaluatorVerbosity,
) -> None:
    print("\n" + "=" * 70, flush=True)
    if execution.track is EvaluationTrack.REDTEAM:
        attack = _require_attack(execution)
        print("FINAL RESULTS", flush=True)
        print("=" * 70, flush=True)
        print(f"Attack Score: {attack.score:.2f}", flush=True)
        print("=" * 70, flush=True)
        if verbosity is not EvaluatorVerbosity.SUMMARY:
            print("\nDETAILED BREAKDOWN:", flush=True)
            print(f"  Attack Findings: {attack.findings_count}", flush=True)
            print(f"  Unique Cells: {attack.unique_cells}", flush=True)
            print(f"  Raw Attack Score: {attack.score_raw:.2f}", flush=True)
        return

    if execution.track is EvaluationTrack.DEFENSE:
        defense = _require_defense(execution)
        print("FINAL RESULTS", flush=True)
        print("=" * 70, flush=True)
        print(f"Defense Score: {defense.score:.2f}", flush=True)
        print("=" * 70, flush=True)
        if verbosity is not EvaluatorVerbosity.SUMMARY:
            print("\nDETAILED BREAKDOWN:", flush=True)
            print(f"  Defense Breaches: {defense.breach_count}", flush=True)
            print(
                f"  False Positives: {defense.false_positives}/{defense.benign_trials}",
                flush=True,
            )
            print(
                f"  False Positive Rate: {defense.false_positive_rate:.2%}",
                flush=True,
            )
        return

    attack = _require_attack(execution)
    defense = _require_defense(execution)
    print("FINAL RESULTS", flush=True)
    print("=" * 70, flush=True)
    print(
        f"Attack Score:  {attack.score:.2f} "
        f"(raw: {attack.score_raw:.2f}, mode: {execution.scoring_mode})",
        flush=True,
    )
    print(f"Defense Score: {defense.score:.2f}", flush=True)
    print(f"Final Score:   {execution.final_score:.2f}", flush=True)
    print("=" * 70, flush=True)
    if verbosity is not EvaluatorVerbosity.SUMMARY:
        print("\nDETAILED BREAKDOWN:", flush=True)
        print(f"  Attack Findings: {attack.findings_count}", flush=True)
        print(f"  Unique Cells: {attack.unique_cells}", flush=True)
        print(f"  Defense Breaches: {defense.breach_count}", flush=True)
        print(
            f"  False Positives: {defense.false_positives}/{defense.benign_trials}",
            flush=True,
        )
        print(
            f"  False Positive Rate: {defense.false_positive_rate:.2%}",
            flush=True,
        )


def run_evaluate(args: argparse.Namespace) -> int:
    track = EvaluationTrack(args.track)
    submission_spec = _build_submission_spec(track, args.submission)

    budget_plan = _resolve_budget_plan(
        track,
        total_budget_s=args.budget_s,
    )
    fixtures_dir = Path(args.fixtures_dir).resolve() if args.fixtures_dir else None
    artifacts = _resolve_artifacts(args.artifacts_dir)
    transcript_file = artifacts.transcript_path if args.save_transcript else None
    framework_events_file = artifacts.framework_events_path if args.save_framework_events else None
    agent_debug_file = artifacts.agent_debug_path if args.save_agent_debug else None

    with RunDiagnostics(
        args.verbosity,
        transcript_file=transcript_file,
        event_log_file=framework_events_file,
        agent_debug_file=agent_debug_file,
    ) as output_controller:
        attack_guardrail_spec = None
        defense_hook_spec = None
        if track is EvaluationTrack.REDTEAM or track is EvaluationTrack.DUAL:
            attack_guardrail_spec = resolve_attack_guardrail_spec()
        if track is EvaluationTrack.DEFENSE or track is EvaluationTrack.DUAL:
            defense_hook_spec = resolve_defense_hook_spec()

        if track is EvaluationTrack.REDTEAM:
            print("\n" + "=" * 70, flush=True)
            print("EVALUATING RED-TEAM SUBMISSION", flush=True)
            print("=" * 70, flush=True)
            print(f"Agent selection: {args.agent}", flush=True)
            print(f"Env selection:   {args.env}", flush=True)
        elif track is EvaluationTrack.DEFENSE:
            print("\n" + "=" * 70, flush=True)
            print("EVALUATING DEFENSE SUBMISSION", flush=True)
            print("=" * 70, flush=True)
            print(f"Agent selection: {args.agent}", flush=True)
            print(f"Env selection:   {args.env}", flush=True)
        else:
            print("\n" + "=" * 70, flush=True)
            print("EVALUATING OFFENSE (Your Attack vs Data-Flow Guardrail)", flush=True)
            print("=" * 70, flush=True)
            print(f"Agent selection: {args.agent}", flush=True)
            print(f"Env selection:   {args.env}", flush=True)

        with ExitStack() as stack:
            attack_cls, guardrail_cls = load_track_modules(
                stack,
                submission_spec.path,
                track,
            )

            if track is EvaluationTrack.REDTEAM:
                if attack_cls is None:
                    raise SystemExit("Submission missing AttackAlgorithm")
                execution = evaluate_redteam(
                    attack_cls,
                    budget_s=budget_plan.total_budget_s,
                    agent_selection=args.agent,
                    env_selection=args.env,
                    fixtures_dir=fixtures_dir,
                    attack_guardrail_spec=attack_guardrail_spec,
                    diagnostics=output_controller,
                )
            elif track is EvaluationTrack.DEFENSE:
                if guardrail_cls is None:
                    raise SystemExit("Submission missing Guardrail")
                execution = evaluate_defense(
                    guardrail_cls,
                    budget_s=budget_plan.total_budget_s,
                    agent_selection=args.agent,
                    env_selection=args.env,
                    fixtures_dir=fixtures_dir,
                    defense_hook_spec=defense_hook_spec,
                    diagnostics=output_controller,
                )
            else:
                if attack_cls is None or guardrail_cls is None:
                    raise SystemExit(
                        "Dual-track submissions must include both attack.py and guardrail.py"
                    )
                execution = evaluate_dual(
                    attack_cls,
                    guardrail_cls,
                    budget_s=budget_plan.total_budget_s,
                    agent_selection=args.agent,
                    env_selection=args.env,
                    fixtures_dir=fixtures_dir,
                    attack_guardrail_spec=attack_guardrail_spec,
                    defense_hook_spec=defense_hook_spec,
                    diagnostics=output_controller,
                )

        _render_summary(execution, verbosity=args.verbosity)
        details = build_evaluation_report(execution, profile=ReportProfile.EVALUATE)

    _write_outputs(
        artifacts=artifacts,
        final_score=details["final_score"],
        details=details,
        transcript_file=transcript_file,
        framework_events_file=framework_events_file,
        agent_debug_file=agent_debug_file,
    )
    return 0
