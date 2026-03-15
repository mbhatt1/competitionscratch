"""
Test command - run evaluation tests with progress tracking.

Supports explicit redteam/dual/defense tracks so local testing can match the
official Kaggle scorer semantics.
"""

import ast
import datetime
import json
import time
import zipfile
from contextlib import ExitStack
from pathlib import Path, PurePosixPath
from typing import Any, Optional

from aicomp_sdk.agents import (
    AgentFactory,
    AgentSelection,
    JsonlAgentDebugSink,
    build_agent_factory,
    parse_agent_selection,
)
from aicomp_sdk.core.env_api import EnvSelection, parse_env_selection

try:
    from rich.console import Console

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


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


def _detect_python_submission_type(content: str) -> str:
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return "unknown"

    class_names = {node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)}
    has_attack = "AttackAlgorithm" in class_names
    has_guardrail = "Guardrail" in class_names

    if has_attack and not has_guardrail:
        return "attack"
    if has_guardrail and not has_attack:
        return "guardrail"
    return "unknown"


def _detect_zip_submission_type(submission_path: Path) -> str:
    try:
        with zipfile.ZipFile(submission_path, "r") as zf:
            member_names = set()
            for info in zf.infolist():
                if info.is_dir():
                    continue
                normalized_path = PurePosixPath(info.filename.replace("\\", "/"))
                if normalized_path.is_absolute() or ".." in normalized_path.parts:
                    continue
                member_names.add(normalized_path.as_posix())
    except zipfile.BadZipFile:
        return "unknown"

    has_attack = "attack.py" in member_names
    has_guardrail = "guardrail.py" in member_names

    if has_attack and has_guardrail:
        return "dual"
    if has_attack:
        return "redteam"
    if has_guardrail:
        return "defense"
    return "unknown"


def _resolve_track(submission_path: Path, requested_track: str) -> str:
    if requested_track != "auto":
        return requested_track

    if submission_path.suffix == ".zip":
        return _detect_zip_submission_type(submission_path)
    if submission_path.suffix == ".py":
        detected = _detect_python_submission_type(submission_path.read_text(encoding="utf-8"))
        if detected == "attack":
            return "redteam"
        if detected == "guardrail":
            return "defense"
    return "unknown"


def _load_track_modules(
    stack: ExitStack, submission_path: Path, track: str
) -> tuple[Optional[type[Any]], Optional[type[Any]]]:
    from aicomp_sdk.evaluation_core import load_from_zip, load_module_from_file

    def load_zip_class(
        *,
        file_name: str,
        module_name: str,
        class_name: str,
    ) -> Optional[type[Any]]:
        module, tmp_dir = load_from_zip(submission_path, module_name, file_name)
        stack.enter_context(tmp_dir)
        if module is None or not hasattr(module, class_name):
            return None
        class_obj = getattr(module, class_name)
        return class_obj if isinstance(class_obj, type) else None

    attack_cls = None
    guardrail_cls = None

    if submission_path.suffix == ".zip":
        if track in {"redteam", "dual"}:
            attack_cls = load_zip_class(
                file_name="attack.py",
                module_name="user_attack",
                class_name="AttackAlgorithm",
            )

        if track in {"defense", "dual"}:
            guardrail_cls = load_zip_class(
                file_name="guardrail.py",
                module_name="user_guardrail",
                class_name="Guardrail",
            )

        return attack_cls, guardrail_cls

    if submission_path.suffix == ".py":
        content = submission_path.read_text(encoding="utf-8")
        detected = _detect_python_submission_type(content)
        if detected == "attack":
            attack_mod = load_module_from_file(submission_path, "user_attack")
            attack_cls = (
                attack_mod.AttackAlgorithm if hasattr(attack_mod, "AttackAlgorithm") else None
            )
        elif detected == "guardrail":
            guard_mod = load_module_from_file(submission_path, "user_guardrail")
            guardrail_cls = guard_mod.Guardrail if hasattr(guard_mod, "Guardrail") else None
        return attack_cls, guardrail_cls

    raise ValueError(f"Unsupported file type: {submission_path.suffix}")


def _resolve_env_selection(requested_env: Optional[str], track: str) -> EnvSelection:
    if requested_env is not None:
        return parse_env_selection(requested_env)
    if track == "redteam":
        return EnvSelection.GYM
    return EnvSelection.SANDBOX


def _with_status(message: str):
    if not RICH_AVAILABLE:
        return None
    return Console().status(message)


def _resolve_agent_factory(
    agent_selection: AgentSelection,
    agent_debug_jsonl: Optional[Path] = None,
    agent_factory: Optional[AgentFactory] = None,
) -> AgentFactory:
    if agent_factory is not None:
        return agent_factory
    debug_sink = None
    if agent_debug_jsonl is not None:
        debug_sink = JsonlAgentDebugSink(agent_debug_jsonl)
    return build_agent_factory(agent_selection, debug_sink=debug_sink)


def _evaluate_attack_once(
    attack_cls,
    attack_budget_s: float,
    agent_factory: AgentFactory,
    env_selection: EnvSelection,
    fixtures_dir: Optional[Path] = None,
) -> tuple[list[dict[str, Any]], float]:
    from aicomp_sdk.evaluation_core import eval_attack

    start = time.time()
    attack_findings = eval_attack(
        attack_cls,
        attack_budget_s,
        agent_factory=agent_factory,
        env_selection=env_selection,
        fixtures_dir=fixtures_dir,
    )
    elapsed = time.time() - start
    return attack_findings, elapsed


def _evaluate_defense_once(
    guardrail_cls,
    defense_budget_s: float,
    agent_factory: AgentFactory,
    env_selection: EnvSelection,
    fixtures_dir: Optional[Path] = None,
) -> tuple[dict[str, Any], float]:
    from aicomp_sdk.evaluation_core import eval_defense

    start = time.time()
    defense_report = eval_defense(
        guardrail_cls,
        defense_budget_s,
        agent_factory=agent_factory,
        env_selection=env_selection,
        fixtures_dir=fixtures_dir,
    )
    elapsed = time.time() - start
    return defense_report, elapsed


def _build_attack_summary(
    attack_findings: list[dict[str, Any]],
    elapsed: float,
) -> dict[str, Any]:
    from aicomp_sdk.evaluation_core import summarize_attack_findings

    return {
        "evaluated": True,
        **summarize_attack_findings(attack_findings),
        "time_taken": elapsed,
    }


def _build_defense_summary(
    defense_report: dict[str, Any],
    elapsed: float,
) -> dict[str, Any]:
    from aicomp_sdk.scoring import score_defense

    breaches = defense_report.get("breach_count", 0)
    fps = defense_report.get("false_positives", 0)
    benign_trials = defense_report.get("benign_trials", 7)
    return {
        "evaluated": True,
        "score": score_defense(defense_report),
        "breach_count": breaches,
        "false_positives": fps,
        "benign_trials": benign_trials,
        "false_positive_rate": fps / max(1, benign_trials),
        "time_taken": elapsed,
    }


def _build_not_evaluated_attack_summary() -> dict[str, Any]:
    return {
        "evaluated": False,
        "score": None,
        "score_raw": None,
        "findings_count": None,
        "unique_cells": None,
        "time_taken": None,
    }


def _build_not_evaluated_defense_summary() -> dict[str, Any]:
    return {
        "evaluated": False,
        "score": None,
        "breach_count": None,
        "false_positives": None,
        "benign_trials": None,
        "false_positive_rate": None,
        "time_taken": None,
    }


def run_redteam_evaluation_with_progress(
    attack_cls,
    attack_budget_s: float,
    agent_selection: AgentSelection,
    env_selection: EnvSelection,
    fixtures_dir: Optional[Path] = None,
    *,
    agent_debug_jsonl: Optional[Path] = None,
    agent_factory: Optional[AgentFactory] = None,
) -> dict[str, Any]:
    """Run the attack-only Kaggle-style evaluation."""
    from aicomp_sdk.cli.main import print_info, print_success

    resolved_agent_factory = _resolve_agent_factory(
        agent_selection,
        agent_debug_jsonl=agent_debug_jsonl,
        agent_factory=agent_factory,
    )

    status = _with_status("[bold blue]Running red-team evaluation...")
    if status is None:
        print_info(f"Running red-team evaluation (time budget: {attack_budget_s:.1f}s)...")
        attack_findings, elapsed = _evaluate_attack_once(
            attack_cls,
            attack_budget_s,
            resolved_agent_factory,
            env_selection,
            fixtures_dir=fixtures_dir,
        )
    else:
        with status:
            print_info(f"Evaluating red-team offense (time budget: {attack_budget_s:.1f}s)")
            attack_findings, elapsed = _evaluate_attack_once(
                attack_cls,
                attack_budget_s,
                resolved_agent_factory,
                env_selection,
                fixtures_dir=fixtures_dir,
            )

    attack_summary = _build_attack_summary(attack_findings, elapsed)
    print_success(
        f"Red-team evaluation complete ({elapsed:.1f}s, {attack_summary['findings_count']} findings)"
    )

    return {
        "track": "redteam",
        "attack": attack_summary,
        "defense": _build_not_evaluated_defense_summary(),
        "final_score": attack_summary["score"],
        "submission_type": "attack_only",
        "scoring_mode": "normalized",
        "agent_selection": agent_selection.value,
        "env_selection": env_selection.value,
    }


def run_defense_evaluation_with_progress(
    guardrail_cls,
    defense_budget_s: float,
    agent_selection: AgentSelection,
    env_selection: EnvSelection,
    fixtures_dir: Optional[Path] = None,
    *,
    agent_debug_jsonl: Optional[Path] = None,
    agent_factory: Optional[AgentFactory] = None,
) -> dict[str, Any]:
    """Run the local-only defense helper track."""
    from aicomp_sdk.cli.main import print_info, print_success

    resolved_agent_factory = _resolve_agent_factory(
        agent_selection,
        agent_debug_jsonl=agent_debug_jsonl,
        agent_factory=agent_factory,
    )

    status = _with_status("[bold blue]Running defense evaluation...")
    if status is None:
        print_info(f"Running defense evaluation (time budget: {defense_budget_s:.1f}s)...")
        defense_report, elapsed = _evaluate_defense_once(
            guardrail_cls,
            defense_budget_s,
            resolved_agent_factory,
            env_selection,
            fixtures_dir=fixtures_dir,
        )
    else:
        with status:
            print_info(f"Evaluating defense (time budget: {defense_budget_s:.1f}s)")
            defense_report, elapsed = _evaluate_defense_once(
                guardrail_cls,
                defense_budget_s,
                resolved_agent_factory,
                env_selection,
                fixtures_dir=fixtures_dir,
            )

    defense_summary = _build_defense_summary(defense_report, elapsed)
    breaches = defense_summary["breach_count"]
    fps = defense_summary["false_positives"]
    print_success(f"Defense evaluation complete ({elapsed:.1f}s, {breaches} breaches, {fps} FPs)")

    return {
        "track": "defense",
        "attack": _build_not_evaluated_attack_summary(),
        "defense": defense_summary,
        "final_score": defense_summary["score"],
        "submission_type": "guardrail_only",
        "agent_selection": agent_selection.value,
        "env_selection": env_selection.value,
    }


def run_dual_evaluation_with_progress(
    attack_cls,
    guardrail_cls,
    attack_budget_s: float,
    defense_budget_s: float,
    agent_selection: AgentSelection,
    env_selection: EnvSelection,
    fixtures_dir: Optional[Path] = None,
    *,
    agent_debug_jsonl: Optional[Path] = None,
    agent_factory: Optional[AgentFactory] = None,
) -> dict[str, Any]:
    """Run the legacy local dual-track evaluation."""
    from aicomp_sdk.cli.main import print_info, print_success
    from aicomp_sdk.scoring import get_score_breakdown

    resolved_agent_factory = _resolve_agent_factory(
        agent_selection,
        agent_debug_jsonl=agent_debug_jsonl,
        agent_factory=agent_factory,
    )

    status = _with_status("[bold blue]Running attack evaluation...")
    if status is None:
        print_info(f"Running attack evaluation (time budget: {attack_budget_s:.1f}s)...")
        attack_findings, attack_elapsed = _evaluate_attack_once(
            attack_cls,
            attack_budget_s,
            resolved_agent_factory,
            env_selection,
            fixtures_dir=fixtures_dir,
        )
    else:
        with status:
            print_info(f"Evaluating offense (time budget: {attack_budget_s:.1f}s)")
            attack_findings, attack_elapsed = _evaluate_attack_once(
                attack_cls,
                attack_budget_s,
                resolved_agent_factory,
                env_selection,
                fixtures_dir=fixtures_dir,
            )
    print_success(
        f"Attack evaluation complete ({attack_elapsed:.1f}s, {len(attack_findings)} findings)"
    )

    status = _with_status("[bold blue]Running defense evaluation...")
    if status is None:
        print_info(f"Running defense evaluation (time budget: {defense_budget_s:.1f}s)...")
        defense_report, defense_elapsed = _evaluate_defense_once(
            guardrail_cls,
            defense_budget_s,
            resolved_agent_factory,
            env_selection,
            fixtures_dir=fixtures_dir,
        )
    else:
        with status:
            print_info(f"Evaluating defense (time budget: {defense_budget_s:.1f}s)")
            defense_report, defense_elapsed = _evaluate_defense_once(
                guardrail_cls,
                defense_budget_s,
                resolved_agent_factory,
                env_selection,
                fixtures_dir=fixtures_dir,
            )
    defense_summary = _build_defense_summary(defense_report, defense_elapsed)
    breaches = defense_summary["breach_count"]
    fps = defense_summary["false_positives"]
    print_success(
        f"Defense evaluation complete ({defense_elapsed:.1f}s, {breaches} breaches, {fps} FPs)"
    )

    attack_summary = _build_attack_summary(attack_findings, attack_elapsed)
    defense_score = defense_summary["score"]
    breakdown = get_score_breakdown(attack_findings, defense_report)

    return {
        "track": "dual",
        "attack": attack_summary,
        "defense": defense_summary,
        "final_score": attack_summary["score"] + defense_score,
        "scoring_mode": breakdown["attack_mode"],
        "submission_type": "dual_track",
        "agent_selection": agent_selection.value,
        "env_selection": env_selection.value,
    }


def print_results_summary(results: dict[str, Any]) -> None:
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

    print("Track:          Dual (Legacy Local)")
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

    total_budget_s = args.budget_s
    if args.quick:
        total_budget_s = 60.0
        print_info("Quick mode: Using reduced time budget (60s total)")

    requested_track = getattr(args, "track", "auto")
    agent_selection = parse_agent_selection(getattr(args, "agent", "auto"))
    track = _resolve_track(submission_path, requested_track)
    env_selection = _resolve_env_selection(getattr(args, "env", None), track)
    fixtures_dir = (
        Path(args.fixtures_dir).resolve() if getattr(args, "fixtures_dir", None) else None
    )
    agent_debug_jsonl = (
        Path(args.agent_debug_jsonl).expanduser().resolve()
        if getattr(args, "agent_debug_jsonl", None)
        else None
    )
    if track == "unknown":
        print_error("Could not determine submission track")
        print_info("Use --track redteam, --track dual, or --track defense")
        return 1

    attack_budget_s = total_budget_s if track == "redteam" else total_budget_s / 2.0
    defense_budget_s = total_budget_s if track == "defense" else total_budget_s / 2.0

    print_info(f"Evaluating submission: {submission_path}")
    print_info(f"Selected track: {track}")
    print_info(f"Agent selection: {agent_selection}")
    print_info(f"Env selection: {env_selection}")
    if fixtures_dir is not None:
        print_info(f"Using fixtures override: {fixtures_dir}")
    if agent_debug_jsonl is not None:
        print_info(f"Agent debug JSONL: {agent_debug_jsonl}")
    if track == "redteam":
        print_info(f"Time budget: {attack_budget_s:.1f}s attack")
    elif track == "defense":
        print_info(f"Time budget: {defense_budget_s:.1f}s defense")
    else:
        print_info(f"Time budget: {attack_budget_s:.1f}s attack, {defense_budget_s:.1f}s defense")
    print()

    try:
        with ExitStack() as stack:
            attack_cls, guardrail_cls = _load_track_modules(stack, submission_path, track)

            if track == "redteam":
                if attack_cls is None:
                    print_error("Submission missing AttackAlgorithm")
                    return 1
                results = run_redteam_evaluation_with_progress(
                    attack_cls,
                    attack_budget_s,
                    agent_selection,
                    env_selection,
                    fixtures_dir=fixtures_dir,
                    agent_debug_jsonl=agent_debug_jsonl,
                )
            elif track == "defense":
                if guardrail_cls is None:
                    print_error("Submission missing Guardrail")
                    return 1
                results = run_defense_evaluation_with_progress(
                    guardrail_cls,
                    defense_budget_s,
                    agent_selection,
                    env_selection,
                    fixtures_dir=fixtures_dir,
                    agent_debug_jsonl=agent_debug_jsonl,
                )
            else:
                if attack_cls is None or guardrail_cls is None:
                    print_error(
                        "Dual-track submissions must include both attack.py and guardrail.py"
                    )
                    return 1
                results = run_dual_evaluation_with_progress(
                    attack_cls,
                    guardrail_cls,
                    attack_budget_s,
                    defense_budget_s,
                    agent_selection,
                    env_selection,
                    fixtures_dir=fixtures_dir,
                    agent_debug_jsonl=agent_debug_jsonl,
                )
    except Exception as e:
        print_error(f"Evaluation failed: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1

    print_results_summary(results)

    run_name = args.name or generate_run_name(submission_path.name)
    try:
        result_file = save_results(run_name, results)
        print_success(f"Results saved to: {result_file}")
        print_info("View history: aicomp history")
        print_info(f"Compare runs: aicomp compare {run_name} <other_run>")
    except Exception as e:
        print_warning(f"Could not save results: {e}")

    return 0
