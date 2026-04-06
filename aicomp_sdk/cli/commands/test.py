"""
Test command - run evaluation tests with progress tracking.

Uses explicit redteam/dual/defense subcommands so local testing can match the
official evaluator track semantics.
"""

import argparse
import datetime
import json
from contextlib import ExitStack
from pathlib import Path
from typing import Any, cast

import aicomp_sdk.evaluation.submissions as evaluation_submissions
from aicomp_sdk.agents import (
    AgentFactory,
    AgentSelection,
    coerce_agent_selection,
)
from aicomp_sdk.cli.commands.options import add_shared_execution_arguments
from aicomp_sdk.core.env.api import EnvSelection, coerce_env_selection
from aicomp_sdk.evaluation.budget_policy import (
    DEFAULT_ATTACK_BUDGET_S,
    DEFAULT_DEFENSE_BUDGET_S,
    DEFAULT_DUAL_TOTAL_BUDGET_S,
)
from aicomp_sdk.evaluation.budget_policy import (
    resolve_standalone_budget_plan as _resolve_budget_plan,
)
from aicomp_sdk.evaluation.diagnostics import (
    EvaluatorVerbosity,
    RunDiagnostics,
    coerce_evaluator_verbosity,
)
from aicomp_sdk.evaluation.ops import (
    AttackGuardrailSpec,
    DefenseHookSpec,
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
from aicomp_sdk.evaluation.tracks import EvaluationTrack


def ensure_history_dir() -> Path:
    """Ensure .aicomp/history/ directory exists."""
    history_dir = Path.cwd() / ".aicomp" / "history"
    history_dir.mkdir(parents=True, exist_ok=True)
    return history_dir


def generate_run_name(submission_name: str) -> str:
    """Generate a unique run name with timestamp."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    clean_name = Path(submission_name).stem
    return f"{clean_name}_{timestamp}"


def save_results(run_name: str, results: dict[str, Any]) -> Path:
    """Save evaluation results to history."""
    history_dir = ensure_history_dir()
    results["run_name"] = run_name
    results["timestamp"] = datetime.datetime.now().isoformat()
    result_file = history_dir / f"{run_name}.json"
    result_file.write_text(json.dumps(results, indent=2), encoding="utf-8")
    return result_file


def _add_common_arguments(parser: argparse.ArgumentParser) -> None:
    add_shared_execution_arguments(
        parser,
        budget_default=None,
        budget_help=(
            "Total evaluation budget in seconds. Defaults to "
            f"{DEFAULT_ATTACK_BUDGET_S:.0f} for redteam, "
            f"{DEFAULT_DEFENSE_BUDGET_S:.0f} for defense, and "
            f"{DEFAULT_DUAL_TOTAL_BUDGET_S:.0f} for dual."
        ),
        agent_help="Blue-agent selection policy for evaluation runs (default: auto)",
        env_help="Attack environment selection. Defaults to sandbox; pass --env gym explicitly.",
        fixtures_help=(
            "Optional fixtures root override. Defaults to AICOMP_FIXTURES_DIR, then packaged "
            "fixtures, then legacy repo fixtures."
        ),
        verbosity_help="Control evaluator diagnostic output (summary, progress, debug)",
    )
    parser.add_argument(
        "--agent-debug-jsonl",
        default=None,
        help=(
            "Optional local JSONL file for raw agent backend debug events. "
            "Contains model requests/responses and tool outputs; keep it local."
        ),
    )
    parser.add_argument("--name", help="Name for this test run (default: auto-generated)")
    parser.add_argument(
        "--transcript-file",
        default=None,
        help="Optional path for raw captured evaluator stdout/stderr transcripts.",
    )
    parser.add_argument(
        "--event-log-file",
        default=None,
        help="Optional path for structured framework event logs.",
    )


def add_test_parser(
    subparsers: argparse._SubParsersAction,
) -> argparse.ArgumentParser:
    test_parser = cast(
        argparse.ArgumentParser,
        subparsers.add_parser(
            "test",
            help="Run local dev evaluation and save history",
            description=(
                "Run the same evaluation engine as `aicomp evaluate`, but optimize for local "
                "iteration: progress output, explicit diagnostics paths, and saved history."
            ),
        ),
    )
    common = argparse.ArgumentParser(add_help=False)
    _add_common_arguments(common)
    track_subparsers = test_parser.add_subparsers(dest="track", required=True)

    redteam_parser = track_subparsers.add_parser(
        EvaluationTrack.REDTEAM.value,
        parents=[common],
        help="Run attack-only evaluation and save the result in history.",
    )
    redteam_parser.add_argument(
        "submission",
        help="Path to a Python attack module or a zip containing attack.py.",
    )

    defense_parser = track_subparsers.add_parser(
        EvaluationTrack.DEFENSE.value,
        parents=[common],
        help="Run guardrail-only evaluation and save the result in history.",
    )
    defense_parser.add_argument(
        "submission",
        help="Path to a Python guardrail module or a zip containing guardrail.py.",
    )

    dual_parser = track_subparsers.add_parser(
        EvaluationTrack.DUAL.value,
        parents=[common],
        help="Run dual-track evaluation from a submission zip and save the result in history.",
    )
    dual_parser.add_argument(
        "submission",
        help="Path to a zip containing attack.py and guardrail.py.",
    )
    return test_parser


def _resolve_env_selection(requested_env: str | EnvSelection | None) -> EnvSelection:
    if requested_env is not None:
        return coerce_env_selection(requested_env)
    return EnvSelection.SANDBOX


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


def _print_progress_start(
    track: EvaluationTrack,
    *,
    attack_budget_s: float,
    defense_budget_s: float,
) -> None:
    from aicomp_sdk.cli.main import print_info

    if track is EvaluationTrack.REDTEAM:
        print_info(f"Running red-team evaluation (time budget: {attack_budget_s:.1f}s)...")
        return

    if track is EvaluationTrack.DEFENSE:
        print_info(f"Running defense evaluation (time budget: {defense_budget_s:.1f}s)...")
        return

    print_info(f"Running attack evaluation (time budget: {attack_budget_s:.1f}s)...")


def _print_progress_complete(execution: EvaluationExecution) -> None:
    from aicomp_sdk.cli.main import print_success

    if execution.track is EvaluationTrack.REDTEAM:
        attack = _require_attack(execution)
        print_success(
            f"Red-team evaluation complete ({attack.time_taken:.1f}s, {attack.findings_count} findings)"
        )
        return

    if execution.track is EvaluationTrack.DEFENSE:
        defense = _require_defense(execution)
        print_success(
            f"Defense evaluation complete ({defense.time_taken:.1f}s, "
            f"{defense.breach_count} breaches, {defense.false_positives} FPs)"
        )
        return

    attack = _require_attack(execution)
    defense = _require_defense(execution)
    print_success(
        f"Attack evaluation complete ({attack.time_taken:.1f}s, {attack.findings_count} findings)"
    )
    print_success(
        f"Defense evaluation complete ({defense.time_taken:.1f}s, "
        f"{defense.breach_count} breaches, {defense.false_positives} FPs)"
    )


def _run_evaluation_with_progress(
    *,
    track: EvaluationTrack,
    attack_cls,
    guardrail_cls,
    budget_s: float | None,
    agent_selection: AgentSelection,
    env_selection: EnvSelection,
    fixtures_dir: Path | None = None,
    verbosity: EvaluatorVerbosity = EvaluatorVerbosity.SUMMARY,
    transcript_file: Path | None = None,
    event_log_file: Path | None = None,
    agent_debug_file: Path | None = None,
    agent_factory: AgentFactory | None = None,
    attack_guardrail_spec: AttackGuardrailSpec | None = None,
    defense_hook_spec: DefenseHookSpec | None = None,
) -> dict[str, Any]:
    budget_plan = _resolve_budget_plan(
        track,
        total_budget_s=budget_s,
    )
    with RunDiagnostics(
        verbosity,
        transcript_file=transcript_file,
        event_log_file=event_log_file,
        agent_debug_file=agent_debug_file,
    ) as output_controller:
        _print_progress_start(
            track,
            attack_budget_s=budget_plan.attack_budget_s,
            defense_budget_s=budget_plan.defense_budget_s,
        )
        if track is EvaluationTrack.REDTEAM:
            if attack_cls is None:
                raise RuntimeError("Red-team evaluation requires AttackAlgorithm")
            execution = evaluate_redteam(
                attack_cls,
                budget_s=budget_plan.total_budget_s,
                agent_selection=agent_selection,
                agent_factory=agent_factory,
                env_selection=env_selection,
                fixtures_dir=fixtures_dir,
                attack_guardrail_spec=attack_guardrail_spec,
                diagnostics=output_controller,
            )
        elif track is EvaluationTrack.DEFENSE:
            if guardrail_cls is None:
                raise RuntimeError("Defense evaluation requires Guardrail")
            execution = evaluate_defense(
                guardrail_cls,
                budget_s=budget_plan.total_budget_s,
                agent_selection=agent_selection,
                agent_factory=agent_factory,
                env_selection=env_selection,
                fixtures_dir=fixtures_dir,
                defense_hook_spec=defense_hook_spec,
                diagnostics=output_controller,
            )
        else:
            if attack_cls is None or guardrail_cls is None:
                raise RuntimeError("Dual-track evaluation requires AttackAlgorithm and Guardrail")
            execution = evaluate_dual(
                attack_cls,
                guardrail_cls,
                budget_s=budget_plan.total_budget_s,
                agent_selection=agent_selection,
                agent_factory=agent_factory,
                env_selection=env_selection,
                fixtures_dir=fixtures_dir,
                attack_guardrail_spec=attack_guardrail_spec,
                defense_hook_spec=defense_hook_spec,
                diagnostics=output_controller,
            )

    _print_progress_complete(execution)
    return build_evaluation_report(execution, profile=ReportProfile.TEST)


def run_redteam_evaluation_with_progress(
    attack_cls,
    budget_s: float,
    agent_selection: AgentSelection,
    env_selection: EnvSelection,
    fixtures_dir: Path | None = None,
    *,
    verbosity: EvaluatorVerbosity = EvaluatorVerbosity.SUMMARY,
    transcript_file: Path | None = None,
    event_log_file: Path | None = None,
    agent_debug_file: Path | None = None,
    agent_factory: AgentFactory | None = None,
) -> dict[str, Any]:
    """Run the attack-only Kaggle-style evaluation."""
    return _run_evaluation_with_progress(
        track=EvaluationTrack.REDTEAM,
        attack_cls=attack_cls,
        guardrail_cls=None,
        budget_s=budget_s,
        agent_selection=agent_selection,
        env_selection=env_selection,
        fixtures_dir=fixtures_dir,
        verbosity=verbosity,
        transcript_file=transcript_file,
        event_log_file=event_log_file,
        agent_debug_file=agent_debug_file,
        agent_factory=agent_factory,
    )


def run_defense_evaluation_with_progress(
    guardrail_cls,
    budget_s: float,
    agent_selection: AgentSelection,
    env_selection: EnvSelection,
    fixtures_dir: Path | None = None,
    *,
    verbosity: EvaluatorVerbosity = EvaluatorVerbosity.SUMMARY,
    transcript_file: Path | None = None,
    event_log_file: Path | None = None,
    agent_debug_file: Path | None = None,
    agent_factory: AgentFactory | None = None,
) -> dict[str, Any]:
    """Run the local-only defense helper track."""
    return _run_evaluation_with_progress(
        track=EvaluationTrack.DEFENSE,
        attack_cls=None,
        guardrail_cls=guardrail_cls,
        budget_s=budget_s,
        agent_selection=agent_selection,
        env_selection=env_selection,
        fixtures_dir=fixtures_dir,
        verbosity=verbosity,
        transcript_file=transcript_file,
        event_log_file=event_log_file,
        agent_debug_file=agent_debug_file,
        agent_factory=agent_factory,
    )


def run_dual_evaluation_with_progress(
    attack_cls,
    guardrail_cls,
    budget_s: float,
    agent_selection: AgentSelection,
    env_selection: EnvSelection,
    fixtures_dir: Path | None = None,
    *,
    verbosity: EvaluatorVerbosity = EvaluatorVerbosity.SUMMARY,
    transcript_file: Path | None = None,
    event_log_file: Path | None = None,
    agent_debug_file: Path | None = None,
    agent_factory: AgentFactory | None = None,
) -> dict[str, Any]:
    """Run the local dual-track evaluation."""
    return _run_evaluation_with_progress(
        track=EvaluationTrack.DUAL,
        attack_cls=attack_cls,
        guardrail_cls=guardrail_cls,
        budget_s=budget_s,
        agent_selection=agent_selection,
        env_selection=env_selection,
        fixtures_dir=fixtures_dir,
        verbosity=verbosity,
        transcript_file=transcript_file,
        event_log_file=event_log_file,
        agent_debug_file=agent_debug_file,
        agent_factory=agent_factory,
    )


def _render_summary(results: dict[str, Any]) -> None:
    """Print formatted results summary for the selected track."""
    track = results["track"]

    print()
    print("=" * 70)
    print("EVALUATION RESULTS")
    print("=" * 70)
    print()

    if track == "redteam":
        attack = results["attack"]
        print("Track:          Red-Team Only")
        print(f"Attack Score:   {attack['score']:.2f}")
        print(f"  - Findings: {attack['findings_count']}")
        print(f"  - Unique cells: {attack['unique_cells']}")
        print(f"  - Raw score: {attack['score_raw']:.2f}")
        print()
        return

    if track == "defense":
        defense = results["defense"]
        print("Track:          Defense Only")
        print(f"Defense Score:  {defense['score']:.2f}")
        print(f"  - Breaches (violations): {defense['breach_count']}")
        print(f"  - False positives: {defense['false_positives']}/{defense['benign_trials']}")
        print(f"  - FP rate: {defense['false_positive_rate']:.1%}")
        print()
        return

    attack = results["attack"]
    defense = results["defense"]
    final = results["final_score"]

    print("Track:          Dual")
    print(f"Attack Score:   {attack['score']:.2f}")
    print(f"  - Findings: {attack['findings_count']}")
    print(f"  - Unique cells: {attack['unique_cells']}")
    print(f"  - Raw score: {attack['score_raw']:.2f}")
    print(f"  - Mode: {results['scoring_mode']}")
    print()
    print(f"Defense Score:  {defense['score']:.2f}")
    print(f"  - Breaches (violations): {defense['breach_count']}")
    print(f"  - False positives: {defense['false_positives']}/{defense['benign_trials']}")
    print(f"  - FP rate: {defense['false_positive_rate']:.1%}")
    print()
    print(f"Final Score:    {final:.2f}")
    print()


def run_test(args) -> int:
    """Execute test command."""
    from aicomp_sdk.cli.main import (
        print_error,
        print_info,
        print_success,
        print_warning,
    )

    submission_path = Path(args.submission)
    if not submission_path.exists():
        print_error(f"Submission not found: {submission_path}")
        return 1

    track = EvaluationTrack(args.track)
    agent_selection = coerce_agent_selection(args.agent)
    raw_verbosity = args.verbosity
    verbosity = (
        EvaluatorVerbosity.SUMMARY
        if raw_verbosity is None
        else coerce_evaluator_verbosity(raw_verbosity)
    )
    env_selection = _resolve_env_selection(args.env)
    fixtures_dir = Path(args.fixtures_dir).resolve() if args.fixtures_dir else None
    transcript_file = (
        Path(args.transcript_file).expanduser().resolve() if args.transcript_file else None
    )
    event_log_file = (
        Path(args.event_log_file).expanduser().resolve() if args.event_log_file else None
    )
    agent_debug_file = (
        Path(args.agent_debug_jsonl).expanduser().resolve() if args.agent_debug_jsonl else None
    )
    budget_plan = _resolve_budget_plan(track, total_budget_s=args.budget_s)
    attack_budget_s = budget_plan.attack_budget_s
    defense_budget_s = budget_plan.defense_budget_s

    print_info(f"Evaluating submission: {submission_path}")
    print_info(f"Selected track: {track.value}")
    print_info(f"Agent selection: {agent_selection}")
    print_info(f"Env selection: {env_selection}")
    if fixtures_dir is not None:
        print_info(f"Using fixtures override: {fixtures_dir}")
    if agent_debug_file is not None:
        print_info(f"Agent debug JSONL: {agent_debug_file}")
    if transcript_file is not None:
        print_info(f"Evaluator transcript: {transcript_file}")
    if event_log_file is not None:
        print_info(f"Evaluator event log: {event_log_file}")
    print_info(f"Evaluator verbosity: {verbosity.value}")
    if track is EvaluationTrack.REDTEAM:
        print_info(f"Time budget: {attack_budget_s:.1f}s attack")
    elif track is EvaluationTrack.DEFENSE:
        print_info(f"Time budget: {defense_budget_s:.1f}s defense")
    else:
        print_info(f"Time budget: {attack_budget_s:.1f}s attack, {defense_budget_s:.1f}s defense")
    print()

    try:
        attack_guardrail_spec = None
        defense_hook_spec = None
        if track is EvaluationTrack.REDTEAM or track is EvaluationTrack.DUAL:
            attack_guardrail_spec = resolve_attack_guardrail_spec()
        if track is EvaluationTrack.DEFENSE or track is EvaluationTrack.DUAL:
            defense_hook_spec = resolve_defense_hook_spec()

        with ExitStack() as stack:
            attack_cls, guardrail_cls = evaluation_submissions.load_track_modules(
                stack, submission_path, track
            )

            if track is EvaluationTrack.REDTEAM and attack_cls is None:
                print_error("Submission missing AttackAlgorithm")
                return 1
            if track is EvaluationTrack.DEFENSE and guardrail_cls is None:
                print_error("Submission missing Guardrail")
                return 1
            if track is EvaluationTrack.DUAL and (attack_cls is None or guardrail_cls is None):
                print_error("Dual-track submissions must include both attack.py and guardrail.py")
                return 1

            results = _run_evaluation_with_progress(
                track=track,
                attack_cls=attack_cls,
                guardrail_cls=guardrail_cls,
                budget_s=budget_plan.total_budget_s,
                agent_selection=agent_selection,
                env_selection=env_selection,
                fixtures_dir=fixtures_dir,
                verbosity=verbosity,
                transcript_file=transcript_file,
                event_log_file=event_log_file,
                agent_debug_file=agent_debug_file,
                attack_guardrail_spec=attack_guardrail_spec,
                defense_hook_spec=defense_hook_spec,
            )
    except Exception as e:
        print_error(f"Evaluation failed: {e}")
        if verbosity is EvaluatorVerbosity.DEBUG:
            import traceback

            traceback.print_exc()
        return 1

    _render_summary(results)

    run_name = args.name or generate_run_name(submission_path.name)
    try:
        result_file = save_results(run_name, results)
        print_success(f"Results saved to: {result_file}")
        print_info("View history: aicomp history")
        print_info(f"Compare runs: aicomp compare {run_name} <other_run>")
    except Exception as e:
        print_warning(f"Could not save results: {e}")

    return 0
