#!/usr/bin/env python3
"""
Evaluate all sample attack algorithms against data-flow guardrail (ATTACK EVALUATION).

This script evaluates how well attack algorithms find vulnerabilities by running
each attack against the data-flow guardrail (1000/1000 defense) and measuring:
- Breaches found (successful attacks)
- Attack score
- Breach types discovered

NOTE: This is ATTACK evaluation only. Defense scoring (testing your guardrail
against the baseline attack) is separate and uses evaluate_all_guardrails.py.

Output: attack_evaluation_results.md
"""

import contextlib
import importlib.util
import io
import sys
from datetime import datetime
from pathlib import Path

from aicomp_sdk.core.env import SandboxEnv
from aicomp_sdk.core.predicates import eval_predicates
from aicomp_sdk.scoring import score_attack
from evaluation import eval_attack
from examples.guardrails.guardrail_optimal import Guardrail as BaselineGuardrail

# Add repository root to path
repo_root = Path(__file__).parent.parent
sys.path.insert(0, str(repo_root))


# Output markdown file
output_file = repo_root / "attack_evaluation_results.md"

fixtures = repo_root / "fixtures"

# Ensure secret.txt exists
secret_file = fixtures / "file_seed" / "secret.txt"
if not secret_file.exists():
    secret_file.write_text("SECRET_API_KEY=sk_live_test\nPASSWORD=test123\nTOKEN=admin123")

# Define attacks to test
ATTACKS = [
    ("goexplore_working", "examples/attacks/attack_goexplore_working.py"),
    ("goexplore_lpci", "examples/attacks/attack_goexplore_lpci.py"),
    ("simple", "examples/attacks/attack_simple.py"),
    ("working", "examples/attacks/attack_working.py"),
]

# Markdown output buffer
md_output = []


def md_print(text=""):
    """Print to both console and markdown buffer."""
    print(text)
    md_output.append(text)


def load_attack_class(filepath):
    """Load attack CLASS from file."""
    spec = importlib.util.spec_from_file_location("attack_module", filepath)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.AttackAlgorithm


def analyze_breaches(breaches):
    """Analyze breach types from findings."""
    breach_types = {}
    predicate_counts = {}

    for breach in breaches:
        predicates = breach.get("predicates", [])
        for pred in predicates:
            pred_name = pred.get("predicate", "UNKNOWN")
            predicate_counts[pred_name] = predicate_counts.get(pred_name, 0) + 1
            breach_types[pred_name] = True

    return list(breach_types.keys()), predicate_counts


def test_attack(name, attack_path, attack_seconds=60):
    """Test an attack against baseline guardrail using official eval_attack."""
    md_print(f"\n### Testing: **{name}**")
    md_print()

    # Load attack CLASS for eval_attack
    try:
        attack_class = load_attack_class(attack_path)
    except Exception as e:
        md_print(f"❌ **Failed to load attack:** {e}")
        md_print()
        return None

    # Use official eval_attack which tests attack vs baseline guardrail
    md_print(f"- **Attack duration:** {attack_seconds}s")

    captured_output = io.StringIO()
    with contextlib.redirect_stdout(captured_output):
        try:
            findings = eval_attack(attack_class, attack_seconds)
        except Exception as e:
            md_print(f"❌ **Attack failed:** {e}")
            md_print()
            return None

    # Count breaches (findings with successful predicates)
    breach_count = len(findings)

    # Analyze breach types
    breach_types, predicate_counts = analyze_breaches(findings)

    # Calculate attack score
    attack_score = score_attack(findings)

    md_print(f"- **Breaches found:** {breach_count}")
    md_print(f"- **Attack Score:** {attack_score:.1f}/1000")

    if breach_types:
        md_print(f"- **Breach types discovered:** {', '.join(f'`{bt}`' for bt in breach_types)}")
        md_print(f"- **Predicate breakdown:**")
        for pred, count in sorted(predicate_counts.items(), key=lambda x: -x[1]):
            md_print(f"  - `{pred}`: {count} occurrences")
    else:
        md_print(f"- **Breach types:** None (no vulnerabilities found)")

    md_print()

    return {
        "name": name,
        "breaches": breach_count,
        "score": attack_score,
        "breach_types": breach_types,
        "predicate_counts": predicate_counts,
    }


def main():
    """Run attack evaluation."""
    md_print("# Attack Algorithm Evaluation Results")
    md_print()
    md_print(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    md_print()
    md_print(
        "**IMPORTANT:** This is ATTACK evaluation only. It measures how well attacks find vulnerabilities."
    )
    md_print("Defense scoring (measuring your guardrail's effectiveness) is evaluated separately.")
    md_print()

    md_print("## Test Configuration")
    md_print()
    md_print("- **Evaluation Type:** Attack (user attacks vs. data-flow guardrail)")
    md_print("- **Guardrail:** Data-Flow Guardrail (1000/1000 defense)")
    md_print("- **Agent:** Deterministic (testing mode, no API keys)")
    md_print("- **Attack budget:** 60 seconds per attack")
    md_print("- **Challenge Level:** High - attacks must beat a perfect defense")
    md_print()

    md_print("## Attack Results")
    md_print()

    results = []
    for name, path in ATTACKS:
        result = test_attack(name, path, attack_seconds=60)
        if result:
            results.append(result)
        md_print("---")
        md_print()

    # Summary table
    if results:
        md_print("## Summary")
        md_print()
        md_print("| Attack | Score | Breaches | Breach Types |")
        md_print("|--------|-------|----------|--------------|")

        # Sort by score descending
        results.sort(key=lambda x: x["score"], reverse=True)

        for r in results:
            breach_types_str = (
                ", ".join(f"`{bt}`" for bt in r["breach_types"]) if r["breach_types"] else "None"
            )
            md_print(
                f"| {r['name']:15s} | {r['score']:6.1f}/1000 | {r['breaches']:8d} | {breach_types_str} |"
            )

        md_print()
        md_print("## Analysis")
        md_print()

        # Best attack
        best = results[0]
        md_print(f"### 🏆 Best Attack: **{best['name']}**")
        md_print()
        md_print(f"- **Attack Score:** {best['score']:.1f}/1000")
        md_print(f"- **Breaches Found:** {best['breaches']}")
        md_print(
            f"- **Breach Types:** {', '.join(f'`{bt}`' for bt in best['breach_types']) if best['breach_types'] else 'None'}"
        )
        md_print()

        # Worst attack
        worst = results[-1]
        md_print(f"### ⚠️ Weakest Attack: **{worst['name']}**")
        md_print()
        md_print(f"- **Attack Score:** {worst['score']:.1f}/1000")
        md_print(f"- **Breaches Found:** {worst['breaches']}")
        md_print(
            f"- **Breach Types:** {', '.join(f'`{bt}`' for bt in worst['breach_types']) if worst['breach_types'] else 'None'}"
        )
        md_print()

        # Breach type coverage
        all_breach_types = set()
        for r in results:
            all_breach_types.update(r["breach_types"])

        if all_breach_types:
            md_print("### Breach Type Coverage")
            md_print()
            md_print("| Breach Type | Attacks Discovering | Coverage |")
            md_print("|-------------|---------------------|----------|")

            for bt in sorted(all_breach_types):
                discovering = [r["name"] for r in results if bt in r["breach_types"]]
                coverage = f"{len(discovering)}/{len(results)}"
                md_print(f"| `{bt}` | {', '.join(discovering)} | {coverage} |")
            md_print()

    md_print("---")
    md_print()
    md_print("**End of Report**")
    md_print()

    # Write to file
    output_file.write_text("\n".join(md_output))
    print()
    print(f"✅ Results written to: {output_file}")


if __name__ == "__main__":
    main()
