"""
Compare command - compare two evaluation results side-by-side.

Loads results from .aicomp/history/ and displays:
- Side-by-side scores
- Improvements/regressions
- Score deltas
"""

import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, cast


def _load_json_result(path: Path) -> dict[str, Any] | None:
    """Load a JSON object result payload from disk."""
    try:
        raw: object = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None

    if not isinstance(raw, dict):
        return None
    if not all(isinstance(key, str) for key in raw):
        return None

    return cast(dict[str, Any], raw)


def load_result(run_identifier: str) -> dict[str, Any] | None:
    """Load a result from history by name or path."""
    # Try as direct path first
    path = Path(run_identifier)
    if path.exists() and path.suffix == ".json":
        return _load_json_result(path)

    # Try in history directory
    history_dir = Path.cwd() / ".aicomp" / "history"

    # Try exact match
    result_file = history_dir / f"{run_identifier}.json"
    if result_file.exists():
        return _load_json_result(result_file)

    # Try as filename
    result_file = history_dir / run_identifier
    if result_file.exists():
        return _load_json_result(result_file)

    return None


def format_delta(value: float, higher_is_better: bool = True) -> str:
    """Format a delta with color coding."""
    if value == 0:
        return "  (no change)"

    is_improvement = (value > 0 and higher_is_better) or (value < 0 and not higher_is_better)

    try:
        from rich.console import Console

        _ = Console()
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


def _metric_block_evaluated(block: Mapping[str, Any]) -> bool:
    return bool(block.get("evaluated", True))


def _format_metric_value(
    value: Any,
    *,
    evaluated: bool,
    formatter: Callable[[Any], str],
) -> str:
    if not evaluated:
        return "N/A"
    return formatter(value)


def _not_run_suffix(evaluated: bool) -> str:
    if evaluated:
        return ""
    return "  (not run)"


def compare_metrics(
    run1: Mapping[str, Any], run2: Mapping[str, Any], metric_filter: str = "all"
) -> None:
    """Compare metrics between two runs."""
    name1 = run1.get("run_name", "Run 1")
    name2 = run2.get("run_name", "Run 2")

    print()
    print("=" * 80)
    print(f"COMPARISON: {name1} vs {name2}")
    print("=" * 80)
    print()

    if metric_filter in ["all", "final"]:
        final1 = run1.get("final_score", 0)
        final2 = run2.get("final_score", 0)
        delta = final2 - final1

        print("Final Score:")
        print(f"  {name1:40s} {final1:8.2f}")
        print(f"  {name2:40s} {final2:8.2f}{format_delta(delta, True)}")
        print()

    if metric_filter in ["all", "attack"]:
        attack1 = run1.get("attack", {})
        attack2 = run2.get("attack", {})
        attack1_evaluated = _metric_block_evaluated(attack1)
        attack2_evaluated = _metric_block_evaluated(attack2)

        print("Attack Metrics:")

        score1 = attack1.get("score", 0)
        score2 = attack2.get("score", 0)
        score1_display = _format_metric_value(
            score1,
            evaluated=attack1_evaluated,
            formatter=lambda value: f"{value:.2f}",
        )
        score2_display = _format_metric_value(
            score2,
            evaluated=attack2_evaluated,
            formatter=lambda value: f"{value:.2f}",
        )
        print("  Score:")
        print(f"    {name1:38s} {score1_display:>8}{_not_run_suffix(attack1_evaluated)}")
        if attack1_evaluated and attack2_evaluated:
            delta = score2 - score1
            print(f"    {name2:38s} {score2_display:>8}{format_delta(delta, True)}")
        else:
            print(f"    {name2:38s} {score2_display:>8}{_not_run_suffix(attack2_evaluated)}")

        findings1 = attack1.get("findings_count", 0)
        findings2 = attack2.get("findings_count", 0)
        findings1_display = _format_metric_value(
            findings1,
            evaluated=attack1_evaluated,
            formatter=lambda value: str(value),
        )
        findings2_display = _format_metric_value(
            findings2,
            evaluated=attack2_evaluated,
            formatter=lambda value: str(value),
        )
        print("  Findings:")
        print(f"    {name1:38s} {findings1_display:>8}{_not_run_suffix(attack1_evaluated)}")
        if attack1_evaluated and attack2_evaluated:
            delta = findings2 - findings1
            print(f"    {name2:38s} {findings2_display:>8}{format_delta(float(delta), True)}")
        else:
            print(f"    {name2:38s} {findings2_display:>8}{_not_run_suffix(attack2_evaluated)}")

        cells1 = attack1.get("unique_cells", 0)
        cells2 = attack2.get("unique_cells", 0)
        cells1_display = _format_metric_value(
            cells1,
            evaluated=attack1_evaluated,
            formatter=lambda value: str(value),
        )
        cells2_display = _format_metric_value(
            cells2,
            evaluated=attack2_evaluated,
            formatter=lambda value: str(value),
        )
        print("  Unique Cells:")
        print(f"    {name1:38s} {cells1_display:>8}{_not_run_suffix(attack1_evaluated)}")
        if attack1_evaluated and attack2_evaluated:
            delta = cells2 - cells1
            print(f"    {name2:38s} {cells2_display:>8}{format_delta(float(delta), True)}")
        else:
            print(f"    {name2:38s} {cells2_display:>8}{_not_run_suffix(attack2_evaluated)}")

        print()

    if metric_filter in ["all", "defense"]:
        defense1 = run1.get("defense", {})
        defense2 = run2.get("defense", {})
        defense1_evaluated = _metric_block_evaluated(defense1)
        defense2_evaluated = _metric_block_evaluated(defense2)

        print("Defense Metrics:")

        score1 = defense1.get("score", 0)
        score2 = defense2.get("score", 0)
        score1_display = _format_metric_value(
            score1,
            evaluated=defense1_evaluated,
            formatter=lambda value: f"{value:.2f}",
        )
        score2_display = _format_metric_value(
            score2,
            evaluated=defense2_evaluated,
            formatter=lambda value: f"{value:.2f}",
        )
        print("  Score:")
        print(f"    {name1:38s} {score1_display:>8}{_not_run_suffix(defense1_evaluated)}")
        if defense1_evaluated and defense2_evaluated:
            delta = score2 - score1
            print(f"    {name2:38s} {score2_display:>8}{format_delta(delta, True)}")
        else:
            print(f"    {name2:38s} {score2_display:>8}{_not_run_suffix(defense2_evaluated)}")

        breaches1 = defense1.get("breach_count", 0)
        breaches2 = defense2.get("breach_count", 0)
        breaches1_display = _format_metric_value(
            breaches1,
            evaluated=defense1_evaluated,
            formatter=lambda value: str(value),
        )
        breaches2_display = _format_metric_value(
            breaches2,
            evaluated=defense2_evaluated,
            formatter=lambda value: str(value),
        )
        print("  Breaches:")
        print(f"    {name1:38s} {breaches1_display:>8}{_not_run_suffix(defense1_evaluated)}")
        if defense1_evaluated and defense2_evaluated:
            delta = breaches2 - breaches1
            print(f"    {name2:38s} {breaches2_display:>8}{format_delta(float(delta), False)}")
        else:
            print(f"    {name2:38s} {breaches2_display:>8}{_not_run_suffix(defense2_evaluated)}")

        fp1 = defense1.get("false_positives", 0)
        fp2 = defense2.get("false_positives", 0)
        fp1_display = _format_metric_value(
            fp1,
            evaluated=defense1_evaluated,
            formatter=lambda value: str(value),
        )
        fp2_display = _format_metric_value(
            fp2,
            evaluated=defense2_evaluated,
            formatter=lambda value: str(value),
        )
        print("  False Positives:")
        print(f"    {name1:38s} {fp1_display:>8}{_not_run_suffix(defense1_evaluated)}")
        if defense1_evaluated and defense2_evaluated:
            delta = fp2 - fp1
            print(f"    {name2:38s} {fp2_display:>8}{format_delta(float(delta), False)}")
        else:
            print(f"    {name2:38s} {fp2_display:>8}{_not_run_suffix(defense2_evaluated)}")

        fpr1 = defense1.get("false_positive_rate", 0)
        fpr2 = defense2.get("false_positive_rate", 0)
        fpr1_display = _format_metric_value(
            fpr1,
            evaluated=defense1_evaluated,
            formatter=lambda value: f"{value:.1%}",
        )
        fpr2_display = _format_metric_value(
            fpr2,
            evaluated=defense2_evaluated,
            formatter=lambda value: f"{value:.1%}",
        )
        print("  FP Rate:")
        print(f"    {name1:38s} {fpr1_display:>8}{_not_run_suffix(defense1_evaluated)}")
        if defense1_evaluated and defense2_evaluated:
            delta = fpr2 - fpr1
            print(f"    {name2:38s} {fpr2_display:>8}{format_delta(delta * 100, False)}")
        else:
            print(f"    {name2:38s} {fpr2_display:>8}{_not_run_suffix(defense2_evaluated)}")

        print()

    print("=" * 80)


def run_compare(args) -> int:
    """Execute compare command."""
    from aicomp_sdk.cli.main import print_error, print_info

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

    try:
        compare_metrics(run1_data, run2_data, args.metric)
        return 0
    except Exception as e:
        print_error(f"Comparison failed: {e}")
        import traceback

        traceback.print_exc()
        return 1
