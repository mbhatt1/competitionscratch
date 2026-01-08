"""
Compare command - compare two evaluation results side-by-side.

Loads results from .aicomp/history/ and displays:
- Side-by-side scores
- Improvements/regressions
- Score deltas
"""

import json
from pathlib import Path
from typing import Any, Dict, Optional


def load_result(run_identifier: str) -> Optional[Dict[str, Any]]:
    """Load a result from history by name or path."""
    # Try as direct path first
    path = Path(run_identifier)
    if path.exists() and path.suffix == ".json":
        return json.loads(path.read_text(encoding="utf-8"))

    # Try in history directory
    history_dir = Path.cwd() / ".aicomp" / "history"

    # Try exact match
    result_file = history_dir / f"{run_identifier}.json"
    if result_file.exists():
        return json.loads(result_file.read_text(encoding="utf-8"))

    # Try as filename
    result_file = history_dir / run_identifier
    if result_file.exists():
        return json.loads(result_file.read_text(encoding="utf-8"))

    return None


def format_delta(value: float, higher_is_better: bool = True) -> str:
    """Format a delta with color coding."""
    if value == 0:
        return "  (no change)"

    is_improvement = (value > 0 and higher_is_better) or (value < 0 and not higher_is_better)

    try:
        from rich.console import Console

        console = Console()
        if is_improvement:
            return (
                f"  [green](+{value:.2f} ↑)[/green]"
                if value > 0
                else f"  [green]({value:.2f} ↓)[/green]"
            )
        else:
            return (
                f"  [red](+{value:.2f} ↓)[/red]" if value > 0 else f"  [red]({value:.2f} ↑)[/red]"
            )
    except ImportError:
        symbol = "↑" if is_improvement else "↓"
        sign = "+" if value > 0 else ""
        return f"  ({sign}{value:.2f} {symbol})"


def compare_metrics(run1: Dict[str, Any], run2: Dict[str, Any], metric_filter: str = "all") -> None:
    """Compare metrics between two runs."""
    from aicomp_sdk.cli.main import print_info

    name1 = run1.get("run_name", "Run 1")
    name2 = run2.get("run_name", "Run 2")

    # Print header
    print()
    print("=" * 80)
    print(f"COMPARISON: {name1} vs {name2}")
    print("=" * 80)
    print()

    # Compare final score
    if metric_filter in ["all", "final"]:
        final1 = run1.get("final_score", 0)
        final2 = run2.get("final_score", 0)
        delta = final2 - final1

        print(f"Final Score:")
        print(f"  {name1:40s} {final1:8.2f}")
        print(f"  {name2:40s} {final2:8.2f}{format_delta(delta, True)}")
        print()

    # Compare attack metrics
    if metric_filter in ["all", "attack"]:
        attack1 = run1.get("attack", {})
        attack2 = run2.get("attack", {})

        print(f"Attack Metrics:")

        score1 = attack1.get("score", 0)
        score2 = attack2.get("score", 0)
        delta = score2 - score1
        print(f"  Score:")
        print(f"    {name1:38s} {score1:8.2f}")
        print(f"    {name2:38s} {score2:8.2f}{format_delta(delta, True)}")

        findings1 = attack1.get("findings_count", 0)
        findings2 = attack2.get("findings_count", 0)
        delta = findings2 - findings1
        print(f"  Findings:")
        print(f"    {name1:38s} {findings1:8d}")
        print(f"    {name2:38s} {findings2:8d}{format_delta(float(delta), True)}")

        cells1 = attack1.get("unique_cells", 0)
        cells2 = attack2.get("unique_cells", 0)
        delta = cells2 - cells1
        print(f"  Unique Cells:")
        print(f"    {name1:38s} {cells1:8d}")
        print(f"    {name2:38s} {cells2:8d}{format_delta(float(delta), True)}")

        print()

    # Compare defense metrics
    if metric_filter in ["all", "defense"]:
        defense1 = run1.get("defense", {})
        defense2 = run2.get("defense", {})

        print(f"Defense Metrics:")

        score1 = defense1.get("score", 0)
        score2 = defense2.get("score", 0)
        delta = score2 - score1
        print(f"  Score:")
        print(f"    {name1:38s} {score1:8.2f}")
        print(f"    {name2:38s} {score2:8.2f}{format_delta(delta, True)}")

        breaches1 = defense1.get("breach_count", 0)
        breaches2 = defense2.get("breach_count", 0)
        delta = breaches2 - breaches1
        print(f"  Breaches:")
        print(f"    {name1:38s} {breaches1:8d}")
        print(f"    {name2:38s} {breaches2:8d}{format_delta(float(delta), False)}")

        fp1 = defense1.get("false_positives", 0)
        fp2 = defense2.get("false_positives", 0)
        delta = fp2 - fp1
        print(f"  False Positives:")
        print(f"    {name1:38s} {fp1:8d}")
        print(f"    {name2:38s} {fp2:8d}{format_delta(float(delta), False)}")

        fpr1 = defense1.get("false_positive_weighted_rate", defense1.get("false_positive_rate", 0))
        fpr2 = defense2.get("false_positive_weighted_rate", defense2.get("false_positive_rate", 0))
        delta = fpr2 - fpr1
        print(f"  Weighted FP Rate:")
        print(f"    {name1:38s} {fpr1:7.1%}")
        print(f"    {name2:38s} {fpr2:7.1%}{format_delta(delta * 100, False)}")

        print()

    print("=" * 80)


def run_compare(args) -> int:
    """Execute compare command."""
    from aicomp_sdk.cli.main import print_error, print_info, print_warning

    # Load both results
    run1_data = load_result(args.run1)
    if run1_data is None:
        print_error(f"Could not find result: {args.run1}")
        print_info("Available results:")
        history_dir = Path.cwd() / ".aicomp" / "history"
        if history_dir.exists():
            for f in sorted(history_dir.glob("*.json")):
                print(f"  - {f.stem}")
        return 1

    run2_data = load_result(args.run2)
    if run2_data is None:
        print_error(f"Could not find result: {args.run2}")
        print_info("Available results:")
        history_dir = Path.cwd() / ".aicomp" / "history"
        if history_dir.exists():
            for f in sorted(history_dir.glob("*.json")):
                print(f"  - {f.stem}")
        return 1

    # Compare
    try:
        compare_metrics(run1_data, run2_data, args.metric)
        return 0
    except Exception as e:
        print_error(f"Comparison failed: {e}")
        import traceback

        traceback.print_exc()
        return 1
