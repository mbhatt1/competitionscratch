"""
Visualize command - generate visualizations from evaluation results.

Creates:
- Markdown reports with detailed breakdowns
- PNG/HTML charts (if matplotlib/plotly available)
- Attack success rate analysis
- Defense effectiveness graphs
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional


def load_result(run_identifier: str) -> Optional[Dict[str, Any]]:
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
        return json.loads(latest_file.read_text(encoding="utf-8"))

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


def create_markdown_report(result: Dict[str, Any], output_path: Path) -> None:
    """Create a markdown report from evaluation results."""
    run_name = result.get("run_name", "Unknown")
    timestamp = result.get("timestamp", "N/A")
    final_score = result.get("final_score", 0)
    scoring_mode = result.get("scoring_mode", "unknown")

    attack = result.get("attack", {})
    defense = result.get("defense", {})

    # Format timestamp
    try:
        dt = datetime.fromisoformat(timestamp)
        formatted_time = dt.strftime("%Y-%m-%d %H:%M:%S")
    except:
        formatted_time = timestamp

    # Build markdown report
    lines = [
        f"# Evaluation Report: {run_name}",
        "",
        f"**Generated:** {formatted_time}",
        "",
        "---",
        "",
        "## Summary",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| **Final Score** | **{final_score:.2f}** |",
        f"| Attack Score | {attack.get('score', 0):.2f} |",
        f"| Defense Score | {defense.get('score', 0):.2f} |",
        f"| Scoring Mode | {scoring_mode} |",
        "",
        "---",
        "",
        "## Attack Performance",
        "",
        "### Overview",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Score | {attack.get('score', 0):.2f} |",
        f"| Raw Score | {attack.get('score_raw', 0):.2f} |",
        f"| Total Findings | {attack.get('findings_count', 0)} |",
        f"| Unique Cells | {attack.get('unique_cells', 0)} |",
        f"| Time Taken | {attack.get('time_taken', 0):.1f}s |",
        "",
    ]

    # Add attack analysis
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
            lines.append("⚠️ **Limited coverage** - consider exploring more diverse attack vectors.")
        lines.append("")
    else:
        lines.append(
            "❌ No security violations found. The target guardrail successfully blocked all attack attempts."
        )
        lines.append("")

    weighted_fp = defense.get("false_positive_weighted", defense.get("false_positives", 0))
    weighted_fp_rate = defense.get(
        "false_positive_weighted_rate",
        defense.get("false_positive_rate", 0),
    )

    lines.extend(
        [
            "---",
            "",
            "## Defense Performance",
            "",
            "### Overview",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Score | {defense.get('score', 0):.2f} |",
            f"| Breaches (violations) | {defense.get('breach_count', 0)} |",
            f"| False Positives | {defense.get('false_positives', 0)}/{defense.get('benign_trials', 7)} |",
            f"| Weighted False Positives | {weighted_fp:.2f}/{defense.get('benign_trials', 7)} |",
            f"| Weighted FP Rate | {weighted_fp_rate:.1%} |",
            f"| Time Taken | {defense.get('time_taken', 0):.1f}s |",
            "",
        ]
    )

    # Add defense analysis
    breaches = defense.get("breach_count", 0)
    fps = defense.get("false_positives", 0)
    fp_rate = weighted_fp_rate

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
            f"✓ **Low weighted false positive rate ({fp_rate:.1%})** - good balance between security and usability."
        )
    else:
        lines.append(
            f"⚠️ **High weighted false positive rate ({fp_rate:.1%})** - may block too many legitimate requests."
        )
    lines.append("")

    lines.extend(
        [
            "---",
            "",
            "## Recommendations",
            "",
        ]
    )

    # Add recommendations based on results
    if final_score < 500:
        lines.append("### Improvement Opportunities")
        lines.append("")
        if attack.get("score", 0) < 250:
            lines.append(
                "- **Strengthen attack strategy:** Try more diverse prompts and attack patterns"
            )
            lines.append("- **Use hooks:** Consider LPCI hook-based attacks for better coverage")
            lines.append(
                "- **Explore systematically:** Use algorithms like GO-EXPLORE for better exploration"
            )
        if defense.get("score", 0) < 250:
            lines.append("- **Improve defense:** Add more sophisticated detection rules")
            lines.append("- **Reduce false positives:** Fine-tune detection thresholds")
            lines.append(
                "- **Use taint tracking:** Implement dataflow analysis for better protection"
            )
        lines.append("")
    else:
        lines.append("### Strong Performance")
        lines.append("")
        lines.append(
            "✅ Your submission shows strong performance! Continue refining your approach."
        )
        lines.append("")

    lines.extend(
        [
            "---",
            "",
            "## Next Steps",
            "",
            "- Compare with other runs: `aicomp compare <run1> <run2>`",
            "- View history: `aicomp history`",
            "- Run new evaluation: `aicomp test <submission>`",
            "",
            f"*Report generated by aicomp CLI v1.0*",
        ]
    )

    # Write report
    output_path.write_text("\n".join(lines), encoding="utf-8")


def create_matplotlib_visualizations(result: Dict[str, Any], output_dir: Path) -> bool:
    """Create matplotlib charts from results."""
    try:
        import matplotlib
        import matplotlib.pyplot as plt

        matplotlib.use("Agg")  # Non-interactive backend
    except ImportError:
        return False

    attack = result.get("attack", {})
    defense = result.get("defense", {})

    # Create figure with subplots
    fig, axes = plt.subplots(2, 2, figsize=(12, 10))
    fig.suptitle(
        f"Evaluation Results: {result.get('run_name', 'Unknown')}", fontsize=16, fontweight="bold"
    )

    # 1. Score breakdown (top-left)
    ax1 = axes[0, 0]
    scores = [attack.get("score", 0), defense.get("score", 0)]
    labels = ["Attack", "Defense"]
    colors = ["#FF6B6B", "#4ECDC4"]
    bars = ax1.bar(labels, scores, color=colors, alpha=0.8)
    ax1.set_ylabel("Score")
    ax1.set_title("Attack vs Defense Scores")
    ax1.set_ylim(0, max(scores) * 1.2 if max(scores) > 0 else 1000)

    # Add value labels on bars
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

    # 2. Attack findings (top-right)
    ax2 = axes[0, 1]
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

    # 3. Defense effectiveness (bottom-left)
    ax3 = axes[1, 0]
    breaches = defense.get("breach_count", 0)
    benign = defense.get("benign_trials", 7)
    fps = defense.get("false_positives", 0)
    blocked = benign - fps

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

    # 4. Overall score gauge (bottom-right)
    ax4 = axes[1, 1]
    final_score = result.get("final_score", 0)
    max_possible = 1000

    # Create a simple gauge chart
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

    # Adjust layout and save
    plt.tight_layout()

    output_file = output_dir / "evaluation_charts.png"
    plt.savefig(output_file, dpi=150, bbox_inches="tight")
    plt.close()

    return True


def run_visualize(args) -> int:
    """Execute visualize command."""
    from aicomp_sdk.cli.main import print_error, print_info, print_success, print_warning

    # Load result
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

    # Determine output directory
    if args.output:
        output_dir = Path(args.output)
    else:
        output_dir = Path.cwd() / ".aicomp" / "visualizations"

    output_dir.mkdir(parents=True, exist_ok=True)

    run_name = result.get("run_name", "unknown")

    try:
        # Create markdown report
        if args.format in ["both", "html"]:
            # Use markdown for HTML format
            markdown_file = output_dir / f"{run_name}_report.md"
            create_markdown_report(result, markdown_file)
            print_success(f"Created markdown report: {markdown_file}")

        # Create visualizations
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
