"""
Test command - run evaluation with progress tracking.

Wraps evaluation.py with:
- Progress bars showing current test
- Time estimates
- Quick mode for faster testing
- Saves results to .aicomp/history/
"""

import datetime
import importlib.util
import json
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from rich.console import Console
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

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


def save_results(run_name: str, results: Dict[str, Any]) -> Path:
    """Save evaluation results to history."""
    history_dir = ensure_history_dir()

    # Add metadata
    results["run_name"] = run_name
    results["timestamp"] = datetime.datetime.now().isoformat()

    # Save to file
    result_file = history_dir / f"{run_name}.json"
    result_file.write_text(json.dumps(results, indent=2), encoding="utf-8")

    return result_file


def load_module_from_file(filepath: Path, module_name: str):
    """Load a Python module from a file."""
    # Remove from sys.modules if already loaded to avoid conflicts
    if module_name in sys.modules:
        del sys.modules[module_name]

    spec = importlib.util.spec_from_file_location(module_name, str(filepath))
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load module from {filepath}")

    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod


def load_from_zip(zip_path: Path, module_name: str, file_name: str):
    """Extract and load module from zip file."""
    tmp = tempfile.mkdtemp(prefix="aicomp_sub_")
    with zipfile.ZipFile(zip_path, "r") as z:
        z.extractall(tmp)

    target = Path(tmp) / file_name
    if not target.exists():
        return None, tmp

    mod = load_module_from_file(target, module_name)
    return mod, tmp


def run_evaluation_with_progress(
    attack_cls, guardrail_cls, attack_seconds: float, defense_seconds: float, verbose: bool = False
) -> Dict[str, Any]:
    """Run evaluation with progress tracking."""
    from aicomp_sdk.cli.main import print_info, print_success
    from aicomp_sdk.scoring import (
        get_score_breakdown,
        score_attack,
        score_attack_raw,
        score_defense,
    )

    # Import evaluation functions
    from evaluation import eval_attack, eval_defense

    results = {}

    # Run attack evaluation
    if RICH_AVAILABLE:
        console = Console()
        with console.status("[bold blue]Running attack evaluation...") as status:
            print_info(f"Evaluating offense (time budget: {attack_seconds:.1f}s)")
            start = time.time()
            attack_findings = eval_attack(attack_cls, attack_seconds)
            elapsed = time.time() - start
            print_success(
                f"Attack evaluation complete ({elapsed:.1f}s, {len(attack_findings)} findings)"
            )
    else:
        print_info(f"Running attack evaluation (time budget: {attack_seconds:.1f}s)...")
        start = time.time()
        attack_findings = eval_attack(attack_cls, attack_seconds)
        elapsed = time.time() - start
        print_success(
            f"Attack evaluation complete ({elapsed:.1f}s, {len(attack_findings)} findings)"
        )

    attack_score = score_attack(attack_findings)
    attack_raw = score_attack_raw(attack_findings)

    results["attack"] = {
        "score": attack_score,
        "score_raw": attack_raw,
        "findings_count": len(attack_findings),
        "unique_cells": len(
            set(
                f.get("cell_signature", {}).get("hash")
                for f in attack_findings
                if f.get("cell_signature")
            )
        ),
        "time_taken": elapsed,
    }

    # Run defense evaluation
    if RICH_AVAILABLE:
        with console.status("[bold blue]Running defense evaluation...") as status:
            print_info(f"Evaluating defense (time budget: {defense_seconds:.1f}s)")
            start = time.time()
            defense_report = eval_defense(guardrail_cls, defense_seconds)
            elapsed = time.time() - start
            breaches = defense_report.get("breach_count", 0)
            fps = defense_report.get("false_positives", 0)
            print_success(
                f"Defense evaluation complete ({elapsed:.1f}s, {breaches} breaches, {fps} FPs)"
            )
    else:
        print_info(f"Running defense evaluation (time budget: {defense_seconds:.1f}s)...")
        start = time.time()
        defense_report = eval_defense(guardrail_cls, defense_seconds)
        elapsed = time.time() - start
        breaches = defense_report.get("breach_count", 0)
        fps = defense_report.get("false_positives", 0)
        print_success(
            f"Defense evaluation complete ({elapsed:.1f}s, {breaches} breaches, {fps} FPs)"
        )

    defense_score = score_defense(defense_report)

    results["defense"] = {
        "score": defense_score,
        "breach_count": defense_report.get("breach_count", 0),
        "false_positives": defense_report.get("false_positives", 0),
        "false_positive_weighted": defense_report.get("false_positive_weighted", 0),
        "benign_trials": defense_report.get("benign_trials", 7),
        "false_positive_weighted_rate": defense_report.get("false_positive_weighted", 0)
        / max(1, defense_report.get("benign_trials", 7)),
        "time_taken": elapsed,
    }

    # Calculate final score
    final = attack_score + defense_score
    breakdown = get_score_breakdown(attack_findings, defense_report)

    results["final_score"] = final
    results["scoring_mode"] = breakdown["attack_mode"]

    return results


def print_results_summary(results: Dict[str, Any]) -> None:
    """Print formatted results summary."""
    from aicomp_sdk.cli.main import print_info, print_success

    attack = results["attack"]
    defense = results["defense"]
    final = results["final_score"]

    print()
    print("=" * 70)
    print("EVALUATION RESULTS")
    print("=" * 70)
    print()
    print(f"Attack Score:   {attack['score']:.2f}")
    print(f"  - Findings: {attack['findings_count']}")
    print(f"  - Unique cells: {attack['unique_cells']}")
    print(f"  - Raw score: {attack['score_raw']:.2f}")
    print(f"  - Mode: {results['scoring_mode']}")
    print()
    print(f"Defense Score:  {defense['score']:.2f}")
    print(f"  - Breaches (violations): {defense['breach_count']}")
    print(f"  - False positives: {defense['false_positives']}/{defense['benign_trials']}")
    print(
        "  - Weighted FP rate: "
        f"{defense['false_positive_weighted_rate']:.1%}"
    )
    print()
    print(f"Final Score:    {final:.2f}")
    print("=" * 70)


def run_test(args) -> int:
    """Execute test command."""
    from aicomp_sdk.cli.main import print_error, print_info, print_success, print_warning

    submission_path = Path(args.submission)

    if not submission_path.exists():
        print_error(f"Submission not found: {submission_path}")
        return 1

    # Adjust time budget for quick mode
    total_seconds = args.seconds
    if args.quick:
        total_seconds = 60.0  # 1 minute total for quick test
        print_info("Quick mode: Using reduced time budget (60s total)")

    attack_seconds = total_seconds / 2.0
    defense_seconds = total_seconds / 2.0

    print_info(f"Evaluating submission: {submission_path}")
    print_info(f"Time budget: {attack_seconds:.1f}s attack, {defense_seconds:.1f}s defense")
    print()

    # Load submission
    try:
        if submission_path.suffix == ".zip":
            # Load from zip
            print_info("Loading submission from zip...")
            attack_mod, tmp1 = load_from_zip(submission_path, "user_attack", "attack.py")
            guard_mod, tmp2 = load_from_zip(submission_path, "user_guardrail", "guardrail.py")

            if attack_mod is None or not hasattr(attack_mod, "AttackAlgorithm"):
                print_error("Submission missing attack.py with AttackAlgorithm")
                return 1
            if guard_mod is None or not hasattr(guard_mod, "Guardrail"):
                print_error("Submission missing guardrail.py with Guardrail")
                return 1

            attack_cls = attack_mod.AttackAlgorithm
            guardrail_cls = guard_mod.Guardrail

        elif submission_path.suffix == ".py":
            # Load single file
            print_info("Loading submission from Python file...")

            # Detect if it's attack or guardrail
            content = submission_path.read_text()

            if "class AttackAlgorithm" in content and "class Guardrail" not in content:
                # Attack only - use baseline guardrail
                print_info("Detected attack submission (will use baseline guardrail)")
                from examples.guardrails.guardrail_optimal import Guardrail as BaselineGuardrail

                attack_mod = load_module_from_file(submission_path, "user_attack")
                if not hasattr(attack_mod, "AttackAlgorithm"):
                    print_error("Missing AttackAlgorithm class")
                    return 1

                attack_cls = attack_mod.AttackAlgorithm
                guardrail_cls = BaselineGuardrail

            elif "class Guardrail" in content and "class AttackAlgorithm" not in content:
                # Guardrail only - use baseline attacker
                print_info("Detected guardrail submission (will use baseline attacker)")
                from aicomp_sdk.attacks.baselines.attacker_goexplore import (
                    AttackAlgorithm as BaselineAttacker,
                )

                guard_mod = load_module_from_file(submission_path, "user_guardrail")
                if not hasattr(guard_mod, "Guardrail"):
                    print_error("Missing Guardrail class")
                    return 1

                attack_cls = BaselineAttacker
                guardrail_cls = guard_mod.Guardrail

            else:
                print_error(
                    "Could not determine submission type. File should contain either AttackAlgorithm or Guardrail class."
                )
                return 1

        else:
            print_error(f"Unsupported file type: {submission_path.suffix}")
            print_info("Supported types: .py, .zip")
            return 1

    except Exception as e:
        print_error(f"Failed to load submission: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1

    # Run evaluation
    try:
        results = run_evaluation_with_progress(
            attack_cls, guardrail_cls, attack_seconds, defense_seconds, args.verbose
        )
    except Exception as e:
        print_error(f"Evaluation failed: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1

    # Print results
    print_results_summary(results)

    # Generate run name
    if args.name:
        run_name = args.name
    else:
        run_name = generate_run_name(submission_path.name)

    # Save results
    try:
        result_file = save_results(run_name, results)
        print()
        print_success(f"Results saved to: {result_file}")
        print_info(f"View history: aicomp history")
        print_info(f"Compare runs: aicomp compare {run_name} <other_run>")
    except Exception as e:
        print_warning(f"Could not save results: {e}")

    return 0
