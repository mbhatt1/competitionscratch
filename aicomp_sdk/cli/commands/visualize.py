"""
Visualize command - generate visualizations from evaluation results.

Creates:
- Markdown reports with detailed breakdowns
- PNG/HTML charts (if matplotlib/plotly available)
- Attack success rate analysis
- Defense effectiveness graphs
"""

import json
from collections.abc import Callable, Mapping
from datetime import datetime
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
    # Handle "latest" special case
    if run_identifier.lower() == "latest":
        history_dir = Path.cwd() / ".aicomp" / "history"
        if not history_dir.exists():
            return None

        # Find most recent file
        json_files = list(history_dir.glob("*.json"))
        if not json_files:
            return None

        latest_file = max(json_files, key=lambda p: p.stat().st_mtime)
        return _load_json_result(latest_file)

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


def _metric_block_evaluated(block: Mapping[str, Any]) -> bool:
    return bool(block.get("evaluated", True))


def _display_metric(
    value: Any,
    *,
    evaluated: bool,
    formatter: Callable[[Any], str],
) -> str:
    if not evaluated:
        return "N/A"
    return formatter(value)


def _append_not_evaluated_section(lines: list[str]) -> None:
    lines.extend(
        [
            "Not evaluated in this run.",
            "",
        ]
    )


def _mark_axis_not_evaluated(ax, title: str) -> None:
    ax.set_title(title)
    kwargs = {
        "ha": "center",
        "va": "center",
        "fontsize": 12,
    }
    if hasattr(ax, "transAxes"):
        kwargs["transform"] = ax.transAxes
    ax.text(0.5, 0.5, "Not evaluated in this run.", **kwargs)
    ax.axis("off")


def _render_single_track_score_panel(ax, label: str, score: float) -> None:
    ax.set_title("Single-Track Result")
    kwargs = {
        "ha": "center",
        "va": "center",
        "fontsize": 12,
        "fontweight": "bold",
    }
    if hasattr(ax, "transAxes"):
        kwargs["transform"] = ax.transAxes
    ax.text(0.5, 0.5, f"Only {label} track evaluated\nScore: {score:.1f}", **kwargs)
    ax.axis("off")


def create_markdown_report(result: Mapping[str, Any], output_path: Path) -> None:
    """Create a markdown report from evaluation results."""
    run_name = result.get("run_name", "Unknown")
    timestamp = result.get("timestamp", "N/A")
    final_score = result.get("final_score", 0)
    scoring_mode = result.get("scoring_mode", "unknown")

    attack = result.get("attack", {})
    defense = result.get("defense", {})
    attack_evaluated = _metric_block_evaluated(attack)
    defense_evaluated = _metric_block_evaluated(defense)

    try:
        dt = datetime.fromisoformat(timestamp)
        formatted_time = dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        formatted_time = timestamp

    lines = [
        f"# Evaluation Report: {run_name}",
        "",
        f"**Generated:** {formatted_time}",
        "",
        "---",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| **Final Score** | **{final_score:.2f}** |",
        f"| Attack Score | {_display_metric(attack.get('score', 0), evaluated=attack_evaluated, formatter=lambda value: f'{value:.2f}')} |",
        f"| Defense Score | {_display_metric(defense.get('score', 0), evaluated=defense_evaluated, formatter=lambda value: f'{value:.2f}')} |",
        f"| Scoring Mode | {scoring_mode} |",
        "",
        "---",
        "",
        "## Attack Performance",
        "",
    ]

    if attack_evaluated:
        lines.extend(
            [
                "### Overview",
                "",
                "| Metric | Value |",
                "|--------|-------|",
                f"| Score | {attack.get('score', 0):.2f} |",
                f"| Raw Score | {attack.get('score_raw', 0):.2f} |",
                f"| Total Findings | {attack.get('findings_count', 0)} |",
                f"| Unique Cells | {attack.get('unique_cells', 0)} |",
                f"| Time Taken | {attack.get('time_taken', 0):.1f}s |",
                "",
            ]
        )

        findings_count = attack.get("findings_count", 0)
        unique_cells = attack.get("unique_cells", 0)

        lines.extend(
            [
                "### Analysis",
                "",
            ]
        )

        if findings_count > 0:
            lines.append(
                f"✅ Found **{findings_count} security violations** across **{unique_cells} unique vulnerable states**."
            )
            lines.append("")

            if unique_cells >= 4:
                lines.append(
                    "🌟 **Excellent coverage** - discovered multiple distinct vulnerabilities!"
                )
            elif unique_cells >= 2:
                lines.append("✓ **Good coverage** - found several different vulnerabilities.")
            else:
                lines.append(
                    "⚠️ **Limited coverage** - consider exploring more diverse attack vectors."
                )
            lines.append("")
        else:
            lines.append(
                "❌ No security violations found. The target guardrail successfully blocked all attack attempts."
            )
            lines.append("")
    else:
        _append_not_evaluated_section(lines)

    lines.extend(
        [
            "---",
            "",
            "## Defense Performance",
            "",
        ]
    )

    if defense_evaluated:
        lines.extend(
            [
                "### Overview",
                "",
                "| Metric | Value |",
                "|--------|-------|",
                f"| Score | {defense.get('score', 0):.2f} |",
                f"| Breaches (violations) | {defense.get('breach_count', 0)} |",
                f"| False Positives | {defense.get('false_positives', 0)}/{defense.get('benign_trials', 7)} |",
                f"| False Positive Rate | {defense.get('false_positive_rate', 0):.1%} |",
                f"| Time Taken | {defense.get('time_taken', 0):.1f}s |",
                "",
            ]
        )

        breaches = defense.get("breach_count", 0)
        fp_rate = defense.get("false_positive_rate", 0)

        lines.extend(
            [
                "### Analysis",
                "",
            ]
        )

        if breaches == 0:
            lines.append("✅ **Perfect defense** - blocked all attack attempts!")
            lines.append("")
        else:
            lines.append(
                f"⚠️ **{breaches} security violation(s) occurred** - attacks got through the guardrail."
            )
            lines.append("")

        if fp_rate == 0:
            lines.append("✅ **No false positives** - all benign requests were allowed.")
        elif fp_rate <= 0.2:
            lines.append(
                f"✓ **Low false positive rate ({fp_rate:.1%})** - good balance between security and usability."
            )
        else:
            lines.append(
                f"⚠️ **High false positive rate ({fp_rate:.1%})** - may block too many legitimate requests."
            )
        lines.append("")
    else:
        _append_not_evaluated_section(lines)

    lines.extend(
        [
            "---",
            "",
            "## Recommendations",
            "",
        ]
    )

    if final_score < 500:
        recommendation_lines: list[str] = [
            "### Improvement Opportunities",
            "",
        ]
        if attack_evaluated and attack.get("score", 0) < 250:
            recommendation_lines.append(
                "- **Strengthen attack strategy:** Try more diverse prompts and attack patterns"
            )
            recommendation_lines.append(
                "- **Use hooks:** Consider LPCI hook-based attacks for better coverage"
            )
            recommendation_lines.append(
                "- **Explore systematically:** Use algorithms like GO-EXPLORE for better exploration"
            )
        if defense_evaluated and defense.get("score", 0) < 250:
            recommendation_lines.append(
                "- **Improve defense:** Add more sophisticated detection rules"
            )
            recommendation_lines.append(
                "- **Reduce false positives:** Fine-tune detection thresholds"
            )
            recommendation_lines.append(
                "- **Use taint tracking:** Implement dataflow analysis for better protection"
            )
        if len(recommendation_lines) == 2:
            recommendation_lines.append("- No additional recommendations for the evaluated track.")
        recommendation_lines.append("")
        lines.extend(recommendation_lines)
    else:
        lines.extend(
            [
                "### Strong Performance",
                "",
                "✅ Your submission shows strong performance! Continue refining your approach.",
                "",
            ]
        )

    lines.extend(
        [
            "---",
            "",
            "## Next Steps",
            "",
            "- Compare with other runs: `aicomp compare <run1> <run2>`",
            "- View history: `aicomp history`",
            "- Run new evaluation: `aicomp test <track> <submission>`",
            "",
            "*Report generated by aicomp CLI v1.0*",
        ]
    )

    output_path.write_text("\n".join(lines), encoding="utf-8")


def create_matplotlib_visualizations(result: Mapping[str, Any], output_dir: Path) -> bool:
    """Create matplotlib charts from results."""
    try:
        import matplotlib
        import matplotlib.pyplot as plt

        matplotlib.use("Agg")  # Non-interactive backend
    except ImportError:
        return False

    attack = result.get("attack", {})
    defense = result.get("defense", {})
    attack_evaluated = _metric_block_evaluated(attack)
    defense_evaluated = _metric_block_evaluated(defense)

    fig, axes = plt.subplots(2, 2, figsize=(12, 10))
    fig.suptitle(
        f"Evaluation Results: {result.get('run_name', 'Unknown')}",
        fontsize=16,
        fontweight="bold",
    )

    ax1 = axes[0, 0]
    if attack_evaluated and defense_evaluated:
        scores = [attack.get("score", 0), defense.get("score", 0)]
        labels = ["Attack", "Defense"]
        colors = ["#FF6B6B", "#4ECDC4"]
        bars = ax1.bar(labels, scores, color=colors, alpha=0.8)
        ax1.set_ylabel("Score")
        ax1.set_title("Attack vs Defense Scores")
        ax1.set_ylim(0, max(scores) * 1.2 if max(scores) > 0 else 1000)

        for bar in bars:
            height = bar.get_height()
            ax1.text(
                bar.get_x() + bar.get_width() / 2.0,
                height,
                f"{height:.1f}",
                ha="center",
                va="bottom",
                fontweight="bold",
            )
    elif attack_evaluated:
        _render_single_track_score_panel(ax1, "Attack", float(attack.get("score", 0)))
    else:
        _render_single_track_score_panel(ax1, "Defense", float(defense.get("score", 0)))

    ax2 = axes[0, 1]
    if attack_evaluated:
        findings = attack.get("findings_count", 0)
        unique = attack.get("unique_cells", 0)
        categories = ["Total Findings", "Unique Cells"]
        values = [findings, unique]
        bars = ax2.bar(categories, values, color=["#95E1D3", "#F38181"], alpha=0.8)
        ax2.set_ylabel("Count")
        ax2.set_title("Attack Coverage")
        ax2.set_ylim(0, max(values) * 1.2 if max(values) > 0 else 10)

        for bar in bars:
            height = bar.get_height()
            ax2.text(
                bar.get_x() + bar.get_width() / 2.0,
                height,
                f"{int(height)}",
                ha="center",
                va="bottom",
                fontweight="bold",
            )
    else:
        _mark_axis_not_evaluated(ax2, "Attack Coverage")

    ax3 = axes[1, 0]
    if defense_evaluated:
        breaches = defense.get("breach_count", 0)
        fps = defense.get("false_positives", 0)

        categories = ["Breaches\n(Lower Better)", "Benign Blocked\n(Lower Better)"]
        values = [breaches, fps]
        bars = ax3.bar(categories, values, color=["#FF6B6B", "#FFA07A"], alpha=0.8)
        ax3.set_ylabel("Count")
        ax3.set_title("Defense Issues")
        ax3.set_ylim(0, max(max(values) * 1.2, 5))

        for bar in bars:
            height = bar.get_height()
            ax3.text(
                bar.get_x() + bar.get_width() / 2.0,
                height,
                f"{int(height)}",
                ha="center",
                va="bottom",
                fontweight="bold",
            )
    else:
        _mark_axis_not_evaluated(ax3, "Defense Issues")

    ax4 = axes[1, 1]
    final_score = result.get("final_score", 0)
    max_possible = 1000

    ax4.barh(["Final Score"], [final_score], color="#4CAF50", alpha=0.8)
    ax4.barh(
        ["Final Score"],
        [max_possible - final_score],
        left=[final_score],
        color="#E0E0E0",
        alpha=0.3,
    )
    ax4.set_xlim(0, max_possible)
    ax4.set_xlabel("Score")
    ax4.set_title("Final Score")
    ax4.text(
        final_score / 2,
        0,
        f"{final_score:.1f}",
        ha="center",
        va="center",
        fontweight="bold",
        fontsize=14,
        color="white",
    )

    plt.tight_layout()

    output_file = output_dir / "evaluation_charts.png"
    plt.savefig(output_file, dpi=150, bbox_inches="tight")
    plt.close()

    return True


def run_visualize(args) -> int:
    """Execute visualize command."""
    from aicomp_sdk.cli.main import (
        print_error,
        print_info,
        print_success,
        print_warning,
    )

    result = load_result(args.run)

    if result is None:
        print_error(f"Could not find result: {args.run}")
        print_info("Available results:")
        history_dir = Path.cwd() / ".aicomp" / "history"
        if history_dir.exists():
            for f in sorted(history_dir.glob("*.json"))[-5:]:
                print(f"  - {f.stem}")
        print_info("Or use: aicomp visualize latest")
        return 1

    if args.output:
        output_dir = Path(args.output)
    else:
        output_dir = Path.cwd() / ".aicomp" / "visualizations"

    output_dir.mkdir(parents=True, exist_ok=True)

    run_name = result.get("run_name", "unknown")

    try:
        if args.format in ["both", "markdown"]:
            markdown_file = output_dir / f"{run_name}_report.md"
            create_markdown_report(result, markdown_file)
            print_success(f"Created markdown report: {markdown_file}")

        if args.format in ["png", "both"]:
            if create_matplotlib_visualizations(result, output_dir):
                chart_file = output_dir / "evaluation_charts.png"
                print_success(f"Created charts: {chart_file}")
            else:
                print_warning("matplotlib not available - skipping chart generation")
                print_info("Install with: pip install matplotlib")

                # Still create markdown as fallback
                markdown_file = output_dir / f"{run_name}_report.md"
                create_markdown_report(result, markdown_file)
                print_success(f"Created markdown report: {markdown_file}")

        print()
        print_info(f"Visualizations saved to: {output_dir}")

        return 0

    except Exception as e:
        print_error(f"Failed to create visualizations: {e}")
        import traceback

        traceback.print_exc()
        return 1
