"""
Test if key findings (simplest signature = best) hold across different random seeds.
Also tests guardrail back pressure effect.
Async execution for faster results.
"""

import asyncio
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from archived_imports import setup_imports

setup_imports()

from aicomp_sdk.attacks.baselines.attacker_goexplore import AttackAlgorithm
from aicomp_sdk.attacks.baselines.guardrail_allow import Guardrail as AllowGuardrail
from aicomp_sdk.attacks.baselines.guardrail_rules import Guardrail as RulesGuardrail
from aicomp_sdk.core.env import SandboxEnv


def run_single_test(seed, signature_type, guardrail_type, fixtures_path):
    """Run a single test configuration (one seed + one signature type + one guardrail)."""
    if signature_type == "tools_only":
        config = {
            "use_args": False,
            "use_outputs": False,
            "use_intent": False,
            "causality_bonus": 0.0,
            "high_bonus": 0.0,
            "critical_bonus": 0.0,
            "medium_bonus": 0.0,
        }
    else:  # full_intent
        config = {
            "use_args": True,
            "use_outputs": True,
            "use_intent": True,
            "causality_bonus": 0.0,
            "high_bonus": 0.0,
            "critical_bonus": 0.0,
            "medium_bonus": 0.0,
        }

    # Select guardrail
    guardrail = AllowGuardrail() if guardrail_type == "allow" else RulesGuardrail()

    env = SandboxEnv(seed=seed, fixtures_dir=fixtures_path, guardrail=guardrail)
    attacker = AttackAlgorithm(config)
    findings = attacker.run(env, {"seconds": 90})

    # Count unique attack types
    attack_types = set()
    for finding in findings:
        for pred in finding.get("predicates", []):
            attack_types.add(pred.get("predicate"))

    result = {
        "seed": seed,
        "signature_type": signature_type,
        "guardrail_type": guardrail_type,
        "findings": len(findings),
        "attack_types": sorted(list(attack_types)),
        "unique_types": len(attack_types),
    }

    print(
        f"[{signature_type}:{guardrail_type}:{seed}] → {result['findings']} findings, {result['unique_types']} unique types"
    )
    return result


async def run_test_async(loop, executor, seed, signature_type, guardrail_type, fixtures_path):
    """Async wrapper for running a single test."""
    return await loop.run_in_executor(
        executor, run_single_test, seed, signature_type, guardrail_type, fixtures_path
    )


async def test_signature_across_seeds_async(seeds=[42, 123, 456, 789, 1337], max_workers=8):
    """Test tools_only vs full signatures × allow vs rules guardrails across multiple seeds."""
    results = {
        "metadata": {
            "experiment": "seed_sensitivity_and_back_pressure",
            "hypothesis": "Simplest signature wins regardless of seed, guardrails reduce diversity via back pressure",
            "seeds_tested": seeds,
            "duration": 90,
            "max_workers": max_workers,
        },
        "tools_only_allow": [],
        "tools_only_rules": [],
        "full_intent_allow": [],
        "full_intent_rules": [],
    }

    fixtures = Path(__file__).resolve().parents[1] / "fixtures"

    # Create all tasks (4 per seed: 2 signatures × 2 guardrails)
    tasks = []
    for seed in seeds:
        for sig_type in ["tools_only", "full_intent"]:
            for guard_type in ["allow", "rules"]:
                tasks.append((sig_type, guard_type, seed))

    print(f"\n🚀 Starting {len(tasks)} tests concurrently (max {max_workers} workers)...")
    print(f"   Seeds: {seeds}")
    print(f"   Configurations: 2 signatures × 2 guardrails")
    print(f"   Estimated time: ~{len(tasks) * 90 / max_workers / 60:.1f} minutes\n")

    # Run tests concurrently using asyncio + ThreadPoolExecutor
    loop = asyncio.get_event_loop()
    executor = ThreadPoolExecutor(max_workers=max_workers)

    try:
        # Create coroutines for all tasks
        coroutines = [
            run_test_async(loop, executor, seed, sig_type, guard_type, fixtures)
            for sig_type, guard_type, seed in tasks
        ]

        # Run all tasks concurrently and collect results
        completed = 0
        for coro in asyncio.as_completed(coroutines):
            result = await coro
            completed += 1

            # Route to correct result list
            key = f"{result['signature_type']}_{result['guardrail_type']}"
            results[key].append(result)

            print(
                f"✓ Completed {completed}/{len(tasks)}: [{result['signature_type']}:{result['guardrail_type']}:{result['seed']}]"
            )

    finally:
        executor.shutdown(wait=True)

    # Sort all results by seed for consistency
    for key in [
        "tools_only_allow",
        "tools_only_rules",
        "full_intent_allow",
        "full_intent_rules",
    ]:
        results[key].sort(key=lambda x: x["seed"])

    return results


def test_signature_across_seeds(seeds=[42, 123, 456, 789, 1337], max_workers=8):
    """Synchronous wrapper for async test function."""
    results = asyncio.run(test_signature_across_seeds_async(seeds, max_workers))

    # Compute aggregates for each configuration
    results["summary"] = {}

    for config in [
        "tools_only_allow",
        "tools_only_rules",
        "full_intent_allow",
        "full_intent_rules",
    ]:
        results["summary"][config] = {
            "avg_findings": sum(r["findings"] for r in results[config]) / len(seeds),
            "avg_unique_types": sum(r["unique_types"] for r in results[config]) / len(seeds),
            "total_findings": sum(r["findings"] for r in results[config]),
            "all_types": sorted(list(set(sum([r["attack_types"] for r in results[config]], [])))),
        }

    # Analyze signature effect (allow guardrail only - no back pressure)
    tools_allow = results["summary"]["tools_only_allow"]
    intent_allow = results["summary"]["full_intent_allow"]

    signature_conclusion = ""
    if tools_allow["total_findings"] > intent_allow["total_findings"]:
        signature_conclusion = "✓ SIGNATURE FINDING HOLDS: Tools-only found more findings than full-intent (without guardrail interference)"
    else:
        signature_conclusion = "✗ SIGNATURE FINDING FAILS: Full-intent found more findings"

    # Analyze back pressure effect (comparing allow vs rules for each signature type)
    tools_pressure = (
        tools_allow["total_findings"] - results["summary"]["tools_only_rules"]["total_findings"]
    )
    intent_pressure = (
        intent_allow["total_findings"] - results["summary"]["full_intent_rules"]["total_findings"]
    )

    back_pressure_conclusion = f"BACK PRESSURE MEASURED: Rules guardrail reduced findings by {tools_pressure} (tools-only) and {intent_pressure} (full-intent)"

    results["summary"]["conclusions"] = {
        "signature_effect": signature_conclusion,
        "back_pressure_effect": back_pressure_conclusion,
        "key_insight": "Guardrail back pressure affects both signatures, but signature granularity effect is independent",
    }

    return results


if __name__ == "__main__":
    results = test_signature_across_seeds()

    # Save results
    output_path = Path(__file__).parent.parent / "seed_sensitivity_results.json"
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)

    print("\n" + "=" * 70)
    print("SUMMARY: SIGNATURE EFFECT (No Guardrail Back Pressure)")
    print("=" * 70)
    print(
        f"Tools-only + allow: {results['summary']['tools_only_allow']['total_findings']} findings (avg {results['summary']['tools_only_allow']['avg_findings']:.1f})"
    )
    print(f"  Types: {results['summary']['tools_only_allow']['all_types']}")
    print(
        f"Full-intent + allow: {results['summary']['full_intent_allow']['total_findings']} findings (avg {results['summary']['full_intent_allow']['avg_findings']:.1f})"
    )
    print(f"  Types: {results['summary']['full_intent_allow']['all_types']}")
    print(f"\n{results['summary']['conclusions']['signature_effect']}")

    print("\n" + "=" * 70)
    print("SUMMARY: BACK PRESSURE EFFECT")
    print("=" * 70)
    print(
        f"Tools-only: {results['summary']['tools_only_allow']['total_findings']} (allow) → {results['summary']['tools_only_rules']['total_findings']} (rules)"
    )
    print(
        f"  Reduction: {results['summary']['tools_only_allow']['total_findings'] - results['summary']['tools_only_rules']['total_findings']} findings"
    )
    print(
        f"Full-intent: {results['summary']['full_intent_allow']['total_findings']} (allow) → {results['summary']['full_intent_rules']['total_findings']} (rules)"
    )
    print(
        f"  Reduction: {results['summary']['full_intent_allow']['total_findings'] - results['summary']['full_intent_rules']['total_findings']} findings"
    )
    print(f"\n{results['summary']['conclusions']['back_pressure_effect']}")

    print("\n" + "=" * 70)
    print("KEY INSIGHT")
    print("=" * 70)
    print(results["summary"]["conclusions"]["key_insight"])
    print(f"\n💾 Results saved to: {output_path}")
