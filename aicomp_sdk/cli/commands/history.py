"""
History command - show past evaluation results.

lists evaluations from .aicomp/history/ with:
- Scores and timestamps
- Submission names
- Filtering and sorting options
"""

import json
from collections.abc import Collection, Mapping
from datetime import datetime
from pathlib import Path
from typing import Any


def load_all_results() -> list[dict[str, Any]]:
    """Load all results from history."""
    history_dir = Path.cwd() / ".aicomp" / "history"

    if not history_dir.exists():
        return []

    results = []
    for result_file in history_dir.glob("*.json"):
        try:
            data = json.loads(result_file.read_text(encoding="utf-8"))
            data["_filename"] = result_file.stem
            results.append(data)
        except Exception:
            # Skip invalid files
            pass

    return results


def format_timestamp(iso_timestamp: str) -> str:
    """Format ISO timestamp to readable format."""
    try:
        dt = datetime.fromisoformat(iso_timestamp)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return iso_timestamp


def print_results_table(results: Collection[Mapping[str, Any]]) -> None:
    """Print results in a formatted table."""
    if not results:
        print("No evaluation results found.")
        return

    # Try to use rich table if available
    try:
        from rich.console import Console
        from rich.table import Table

        console = Console()
        table = Table(show_header=True, header_style="bold blue")

        table.add_column("Run Name", style="cyan", no_wrap=False)
        table.add_column("Timestamp", style="dim")
        table.add_column("Final", justify="right", style="bold")
        table.add_column("Attack", justify="right", style="green")
        table.add_column("Defense", justify="right", style="magenta")
        table.add_column("Findings", justify="right")
        table.add_column("Breaches", justify="right")
        table.add_column("FPs", justify="right")

        for result in results:
            run_name = result.get("run_name", result.get("_filename", "Unknown"))
            timestamp = format_timestamp(result.get("timestamp", "N/A"))
            final_score = result.get("final_score", 0)
            attack_score = result.get("attack", {}).get("score", 0)
            defense_score = result.get("defense", {}).get("score", 0)
            findings = result.get("attack", {}).get("findings_count", 0)
            breaches = result.get("defense", {}).get("breach_count", 0)
            fps = result.get("defense", {}).get("false_positives", 0)

            table.add_row(
                run_name,
                timestamp,
                f"{final_score:.2f}",
                f"{attack_score:.2f}",
                f"{defense_score:.2f}",
                str(findings),
                str(breaches),
                str(fps),
            )

        console.print(table)

    except ImportError:
        # Fall back to simple table
        print()
        print(
            f"{'Run Name':<35} {'Timestamp':<20} {'Final':>8} {'Attack':>8} {'Defense':>8} {'Findings':>9} {'Breaches':>9} {'FPs':>5}"
        )
        print("-" * 120)

        for result in results:
            run_name = result.get("run_name", result.get("_filename", "Unknown"))
            timestamp = format_timestamp(result.get("timestamp", "N/A"))
            final_score = result.get("final_score", 0)
            attack_score = result.get("attack", {}).get("score", 0)
            defense_score = result.get("defense", {}).get("score", 0)
            findings = result.get("attack", {}).get("findings_count", 0)
            breaches = result.get("defense", {}).get("breach_count", 0)
            fps = result.get("defense", {}).get("false_positives", 0)

            # Truncate run name if too long
            if len(run_name) > 34:
                run_name = run_name[:31] + "..."

            print(
                f"{run_name:<35} {timestamp:<20} {final_score:8.2f} {attack_score:8.2f} {defense_score:8.2f} {findings:9d} {breaches:9d} {fps:5d}"
            )

        print()


def run_history(args) -> int:
    """Execute history command."""
    from aicomp_sdk.cli.main import print_info, print_warning

    # Load all results
    results = load_all_results()

    if not results:
        print_warning("No evaluation results found.")
        print_info("Run evaluations with: aicomp test <submission>")
        return 0

    # Filter if requested
    if args.filter:
        filter_term = args.filter.lower()
        results = [r for r in results if filter_term in r.get("run_name", "").lower()]

        if not results:
            print_warning(f"No results matching filter: {args.filter}")
            return 0

    # Sort results
    if args.sort == "date":
        results.sort(key=lambda r: r.get("timestamp", ""), reverse=True)
    elif args.sort == "score":
        results.sort(key=lambda r: r.get("final_score", 0), reverse=True)
    elif args.sort == "name":
        results.sort(key=lambda r: r.get("run_name", ""))

    # Limit results
    if args.limit > 0 and len(results) > args.limit:
        results = results[: args.limit]
        print_info(f"Showing top {args.limit} results (total: {len(load_all_results())})")

    # Print results
    print_results_table(results)

    # Show summary
    if results:
        print()
        best = max(results, key=lambda r: r.get("final_score", 0))
        print_info(
            f"Best score: {best.get('final_score', 0):.2f} ({best.get('run_name', 'Unknown')})"
        )
        print_info(f"Total runs: {len(load_all_results())}")
        print()
        print_info("Commands:")
        print("  Compare runs:  aicomp compare <run1> <run2>")
        print("  Visualize:     aicomp visualize <run_name>")

    return 0
