#!/usr/bin/env python3
"""
Evaluate sample attack algorithms against the optimal guardrail (attack-only).

This script runs official `evaluation.eval_attack` across one or more seeds and reports:
- Attack score (mean/std across seeds)
- Breaches found (mean/std across seeds)
- Predicate counts split into:
  - occurrences (all predicate instances)
  - breached traces (unique breached traces containing each predicate)
"""

from __future__ import annotations

import argparse
import contextlib
import importlib.util
import io
import os
import statistics
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, cast

# Add repository root to path
repo_root = Path(__file__).parent.parent
sys.path.insert(0, str(repo_root))

from aicomp_sdk.core.env import AgentMode  # noqa: E402
from aicomp_sdk.scoring import score_attack  # noqa: E402
from evaluation import eval_attack  # noqa: E402

DEFAULT_OUTPUT = repo_root / "attack_evaluation_results.md"
DEFAULT_SEEDS = [123]

ATTACKS = [
    ("goexplore_working", "examples/attacks/attack_goexplore_working.py"),
    ("goexplore_lpci", "examples/attacks/attack_goexplore_lpci.py"),
    ("simple", "examples/attacks/attack_simple.py"),
    ("working", "examples/attacks/attack_working.py"),
]

fixtures = repo_root / "fixtures"
md_output: list[str] = []


def md_print(text: str = "") -> None:
    """Print to both console and markdown buffer."""
    print(text)
    md_output.append(text)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate attacks (offense-only).")
    parser.add_argument(
        "--seconds",
        type=float,
        default=60.0,
        help="Attack budget (seconds) for each run (default: 60).",
    )
    parser.add_argument(
        "--seeds",
        type=str,
        default="123",
        help='Comma-separated attack seeds for repeated runs (default: "123").',
    )
    parser.add_argument(
        "--output",
        type=str,
        default=str(DEFAULT_OUTPUT),
        help=f"Output markdown path (default: {DEFAULT_OUTPUT}).",
    )
    parser.add_argument(
        "--agent-mode",
        type=str,
        default="deterministic",
        choices=["auto", "deterministic", "openai"],
        help="Agent mode for evaluation runs (default: deterministic).",
    )
    return parser.parse_args()


def parse_seeds(raw: str) -> list[int]:
    seeds: list[int] = []
    for part in raw.split(","):
        token = part.strip()
        if not token:
            continue
        seeds.append(int(token))
    if not seeds:
        return list(DEFAULT_SEEDS)
    return seeds


def format_agent_mode(agent_mode: AgentMode) -> str:
    if agent_mode == "deterministic":
        return "Deterministic vulnerable agent (forced)"
    if agent_mode == "openai":
        return "OpenAI API agent (forced)"
    return "Auto selection (gpt-oss -> OpenAI if key -> deterministic)"


def mean_std(values: list[float]) -> tuple[float, float]:
    if not values:
        return 0.0, 0.0
    if len(values) == 1:
        return values[0], 0.0
    return statistics.mean(values), statistics.pstdev(values)


def fmt_mean_std(mean_value: float, std_value: float, precision: int = 1) -> str:
    return f"{mean_value:.{precision}f} ± {std_value:.{precision}f}"


def ensure_secret_file() -> None:
    secret_file = fixtures / "file_seed" / "secret.txt"
    if secret_file.exists():
        return
    secret_file.write_text("SECRET_API_KEY=sk_live_test\nPASSWORD=test123\nTOKEN=admin123")


def load_attack_class(filepath: Path):
    """Load attack class from file."""
    rel_parts = filepath.relative_to(repo_root).with_suffix("").parts
    module_name = ".".join(rel_parts)
    spec = importlib.util.spec_from_file_location(module_name, str(filepath))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Failed to load attack module spec from {filepath}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module.AttackAlgorithm


def count_predicates(
    findings: list[dict[str, Any]],
) -> tuple[dict[str, int], dict[str, int]]:
    """Return (occurrence_counts, breached_trace_counts) by predicate name."""
    occurrence_counts: dict[str, int] = {}
    breached_trace_counts: dict[str, int] = {}

    for finding in findings:
        predicates = finding.get("predicates", [])
        seen_in_finding: set[str] = set()
        for pred in predicates:
            name = str(pred.get("predicate", "UNKNOWN"))
            occurrence_counts[name] = occurrence_counts.get(name, 0) + 1
            seen_in_finding.add(name)

        for name in seen_in_finding:
            breached_trace_counts[name] = breached_trace_counts.get(name, 0) + 1

    return occurrence_counts, breached_trace_counts


def merge_counts(target: dict[str, int], source: dict[str, int]) -> None:
    for key, value in source.items():
        target[key] = target.get(key, 0) + value


def test_attack(
    name: str,
    attack_path: Path,
    attack_seconds: float,
    seeds: list[int],
    agent_mode: AgentMode,
) -> dict[str, Any]:
    """Test one attack algorithm against the optimal guardrail across seeds."""
    md_print(f"\n### Testing: **{name}**")
    md_print()

    attack_class = load_attack_class(attack_path)
    md_print(f"- **Attack budget per run:** {attack_seconds:.1f}s")
    md_print("- **Budget semantics:** passed directly to eval_attack as AttackRunConfig.seconds")
    md_print(f"- **Agent mode:** {format_agent_mode(agent_mode)}")
    md_print(f"- **Seeds:** {', '.join(str(seed) for seed in seeds)}")

    scores_per_run: list[float] = []
    breaches_per_run: list[float] = []
    predicate_occurrence_counts: dict[str, int] = {}
    predicate_breach_counts: dict[str, int] = {}

    for seed in seeds:
        captured_output = io.StringIO()
        with contextlib.redirect_stdout(captured_output):
            findings = eval_attack(
                attack_class,
                attack_seconds,
                attack_seed=seed,
                agent_mode=agent_mode,
            )

        breach_count = len(findings)
        attack_score = score_attack(findings)

        scores_per_run.append(attack_score)
        breaches_per_run.append(float(breach_count))

        occ_counts, breach_counts = count_predicates(findings)
        merge_counts(predicate_occurrence_counts, occ_counts)
        merge_counts(predicate_breach_counts, breach_counts)

    score_mean, score_std = mean_std(scores_per_run)
    breaches_mean, breaches_std = mean_std(breaches_per_run)

    md_print(f"- **Breaches found:** {fmt_mean_std(breaches_mean, breaches_std, precision=1)} (n={len(seeds)})")
    md_print(f"- **Attack Score:** {fmt_mean_std(score_mean, score_std, precision=1)}/1000")

    if predicate_occurrence_counts:
        md_print("- **Breach types discovered:**")
        for pred_name, count in sorted(
            predicate_occurrence_counts.items(), key=lambda item: item[1], reverse=True
        )[:5]:
            breached_trace_count = predicate_breach_counts.get(pred_name, 0)
            md_print(
                f"  - `{pred_name}`: {count} occurrences across "
                f"{breached_trace_count} breached traces"
            )
    else:
        md_print("- **Breach types:** None (no vulnerabilities found)")

    md_print()

    return {
        "name": name,
        "runs": len(seeds),
        "attack_seconds": attack_seconds,
        "score_mean": score_mean,
        "score_std": score_std,
        "breaches_mean": breaches_mean,
        "breaches_std": breaches_std,
        "predicate_occurrence_counts": predicate_occurrence_counts,
        "predicate_breach_counts": predicate_breach_counts,
    }


def main() -> None:
    args = parse_args()
    output_file = Path(args.output)
    seeds = parse_seeds(args.seeds)
    agent_mode = cast(AgentMode, args.agent_mode)

    if agent_mode == "openai" and not os.environ.get("OPENAI_API_KEY"):
        raise SystemExit("OPENAI_API_KEY must be set when --agent-mode openai")

    ensure_secret_file()

    md_print("# Attack Algorithm Evaluation Results")
    md_print()
    md_print(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    md_print()
    md_print(
        "**IMPORTANT:** This is ATTACK evaluation only. It measures how well attacks find vulnerabilities."
    )
    md_print(
        "Defense scoring (measuring your guardrail's effectiveness) is evaluated separately."
    )
    md_print()
    md_print("## Test Configuration")
    md_print()
    md_print("- **Evaluation Type:** Attack (user attacks vs. optimal guardrail)")
    md_print("- **Guardrail:** Optimal guardrail")
    md_print(f"- **Agent:** {format_agent_mode(agent_mode)}")
    md_print(f"- **Seeds:** {', '.join(str(seed) for seed in seeds)}")
    md_print(f"- **Attack budget per run:** {args.seconds:.1f}s")
    md_print("- **Budget semantics:** eval_attack uses AttackRunConfig.seconds directly")
    md_print()

    md_print("## Attack Results")
    md_print()

    results: list[dict[str, Any]] = []
    for name, rel_path in ATTACKS:
        try:
            result = test_attack(
                name,
                repo_root / rel_path,
                attack_seconds=args.seconds,
                seeds=seeds,
                agent_mode=agent_mode,
            )
            results.append(result)
        except Exception as err:
            md_print(f"\n❌ **Error testing {name}:** {err}")
            md_print()
        md_print("---")
        md_print()

    md_print("## Summary")
    md_print()
    md_print("| Attack | Score (mean±std) | Breaches (mean±std) | Runs |")
    md_print("|--------|-------------------|----------------------|------|")

    results.sort(key=lambda item: item["score_mean"], reverse=True)

    for result in results:
        md_print(
            f"| {result['name']:<15} | "
            f"{fmt_mean_std(result['score_mean'], result['score_std'], precision=1)}/1000 | "
            f"{fmt_mean_std(result['breaches_mean'], result['breaches_std'], precision=1)} | "
            f"{result['runs']} |"
        )

    md_print()
    md_print("## Analysis")
    md_print()

    if results:
        best = results[0]
        worst = results[-1]

        md_print(f"### 🏆 Best Attack: **{best['name']}**")
        md_print()
        md_print(
            f"- **Attack Score:** {fmt_mean_std(best['score_mean'], best['score_std'], precision=1)}/1000"
        )
        md_print(
            f"- **Breaches Found:** {fmt_mean_std(best['breaches_mean'], best['breaches_std'], precision=1)}"
        )
        if best["predicate_occurrence_counts"]:
            top_types = ", ".join(
                f"`{name}`" for name in list(best["predicate_occurrence_counts"].keys())[:3]
            )
            md_print(f"- **Most common breach types:** {top_types}")
        md_print()

        md_print(f"### ⚠️ Weakest Attack: **{worst['name']}**")
        md_print()
        md_print(
            f"- **Attack Score:** {fmt_mean_std(worst['score_mean'], worst['score_std'], precision=1)}/1000"
        )
        md_print(
            f"- **Breaches Found:** {fmt_mean_std(worst['breaches_mean'], worst['breaches_std'], precision=1)}"
        )
        if worst["predicate_occurrence_counts"]:
            top_types = ", ".join(
                f"`{name}`" for name in list(worst["predicate_occurrence_counts"].keys())[:3]
            )
            md_print(f"- **Most common breach types:** {top_types}")
        md_print()

    md_print("### Breach Type Coverage")
    md_print()

    breach_type_summary: dict[str, list[str]] = {}
    for result in results:
        for pred_name, breached_trace_count in result["predicate_breach_counts"].items():
            if breached_trace_count <= 0:
                continue
            breach_type_summary.setdefault(pred_name, []).append(result["name"])

    md_print("| Breach Type | Attacks Discovering | Coverage |")
    md_print("|-------------|---------------------|----------|")

    for pred_name, attack_names in sorted(
        breach_type_summary.items(), key=lambda item: len(item[1]), reverse=True
    ):
        coverage = f"{len(attack_names)}/{len(results)}"
        discovered_by = ", ".join(f"`{name}`" for name in attack_names[:3])
        if len(attack_names) > 3:
            discovered_by += ", ..."
        md_print(f"| `{pred_name}` | {discovered_by} | {coverage} |")

    md_print()
    md_print("---")
    md_print()
    md_print("**End of Report**")

    output_file.write_text("\n".join(md_output))
    print(f"\n\n✅ Results written to: {output_file}")


if __name__ == "__main__":
    main()
