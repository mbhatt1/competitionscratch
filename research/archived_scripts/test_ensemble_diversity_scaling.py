#!/usr/bin/env python3
"""
Ensemble Diversity Scaling Experiment (FULLY ASYNC)
All ensemble sizes run concurrently for maximum speed
"""

import asyncio
import json
import os
import sys
from collections import defaultdict
from datetime import datetime

from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from archived_imports import (
    create_archived_sandbox_env,
    get_fixtures_dir,
    require_openai_key,
    setup_imports,
)

repo_root = setup_imports()

from aicomp_sdk.attacks.baselines.attacker_goexplore import AttackAlgorithm
from aicomp_sdk.attacks.baselines.guardrail_allow import Guardrail as AllowGuardrail
from tests.integration.test_verify_findings import detect_real_attacks

# Verify API key
if not os.environ.get("OPENAI_API_KEY"):
    print("ERROR: OPENAI_API_KEY required")
    sys.exit(1)
require_openai_key()

fixtures = get_fixtures_dir()


def extract_diversity_stats(findings):
    """Extract statistics focused on unique attack types (diversity)"""
    stats = {
        "total_findings": len(findings),
        "real_attacks": 0,
        "tool_calls": 0,
        "attack_types": set(),
    }

    for f in findings:
        events = f.get("trace", {}).get("tool_events", [])
        stats["tool_calls"] += len(events)

        real = detect_real_attacks(events)
        for attack in real:
            stats["real_attacks"] += 1
            atype = attack.get("type", "UNKNOWN")
            stats["attack_types"].add(atype)

    stats["attack_types"] = sorted(list(stats["attack_types"]))
    stats["num_unique_types"] = len(stats["attack_types"])

    return stats


async def run_simple_agent_async(seed, time_budget=60, agent_id=""):
    """Run a single simple agent with given random seed (async wrapper)"""
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, run_simple_agent_sync, seed, time_budget)
    print(
        f"  ✓ {agent_id} (seed={seed}) completed: {result[1]['total_findings']} findings, {result[1]['num_unique_types']} types"
    )
    return result


def run_simple_agent_sync(seed, time_budget=60):
    """Run a single simple agent with given random seed (sync implementation)"""
    env = create_archived_sandbox_env(
        seed=seed,
        fixtures_dir=fixtures,
        guardrail=AllowGuardrail(),
        agent_selection="openai",
    )

    config = {
        "max_turns": 6,
        "branch_batch": 12,
        "use_intent": False,
        "use_args": False,
        "use_outputs": False,
        "causality_bonus": 0,
        "high_bonus": 0,
        "critical_bonus": 0,
        "medium_bonus": 0,
        "target_shell": False,
    }

    atk = AttackAlgorithm(config)
    findings = atk.run(env, {"time_budget_s": time_budget})
    stats = extract_diversity_stats(findings)
    stats["seed"] = seed

    return findings, stats


async def run_all_ensembles_concurrent(ensemble_sizes, time_per_agent=60, max_parallel=20):
    """Run ALL agents from ALL ensemble sizes concurrently"""
    print(
        f"\nLaunching ALL {sum(ensemble_sizes)} agents concurrently (max {max_parallel} parallel)..."
    )

    base_seed = 42

    # Create all tasks upfront
    all_tasks = []
    task_metadata = []  # Track which ensemble each task belongs to

    for n in ensemble_sizes:
        seeds = [base_seed + i * 100 for i in range(n)]
        for seed in seeds:
            agent_id = f"N={n:3d} Agent#{len([m for m in task_metadata if m['n'] == n]) + 1:3d}"
            task = run_simple_agent_async(seed, time_per_agent, agent_id)
            all_tasks.append(task)
            task_metadata.append({"n": n, "seed": seed})

    print(f"Total agents to run: {len(all_tasks)}")
    print(
        f"Estimated wall time: ~{(len(all_tasks) / max_parallel) * time_per_agent / 60:.1f} minutes\n"
    )

    # Run all tasks with semaphore to limit concurrency
    semaphore = asyncio.Semaphore(max_parallel)

    async def run_with_semaphore(task):
        async with semaphore:
            return await task

    # Execute all tasks concurrently
    all_results = await asyncio.gather(*[run_with_semaphore(task) for task in all_tasks])

    # Group results by ensemble size
    ensemble_results = {n: {"findings": [], "stats": []} for n in ensemble_sizes}

    for i, (findings, stats) in enumerate(all_results):
        n = task_metadata[i]["n"]
        ensemble_results[n]["findings"].extend(findings)
        ensemble_results[n]["stats"].append(stats)

    # Compute combined stats for each ensemble
    final_results = []
    for n in ensemble_sizes:
        combined_stats = extract_diversity_stats(ensemble_results[n]["findings"])
        final_results.append(
            {
                "n_agents": n,
                "time_per_agent": time_per_agent,
                "total_time": n * time_per_agent,
                "max_parallel": max_parallel,
                "individual_results": ensemble_results[n]["stats"],
                "combined": combined_stats,
            }
        )

    return final_results


async def main():
    print("=" * 70)
    print("ENSEMBLE DIVERSITY SCALING EXPERIMENT (FULLY ASYNC)")
    print("=" * 70)
    print("\nHypothesis: N simple agents discover more unique attack")
    print("types than 1 enhanced agent (log-linear scaling)")
    print("\nConfiguration: Simple agents (tools_only signature)")
    print("Variation: Random seed only (experimental validity)")
    print("Optimization: ALL ensemble sizes run concurrently!")
    print(f"\nStarted: {datetime.now().strftime('%H:%M:%S')}")

    ensemble_sizes = [1, 3, 5, 10, 20, 50, 100]
    time_per_agent = 60  # seconds
    max_parallel = 20  # concurrent agents (increased for full concurrency)

    total_agents = sum(ensemble_sizes)

    print(f"\nTesting ensemble sizes: {ensemble_sizes}")
    print(f"Total agents: {total_agents}")
    print(f"Max parallel: {max_parallel}")
    print(
        f"Estimated wall time: ~{(total_agents / max_parallel) * time_per_agent / 60:.1f} minutes\n"
    )

    start_time = datetime.now()

    all_results = await run_all_ensembles_concurrent(ensemble_sizes, time_per_agent, max_parallel)

    end_time = datetime.now()
    elapsed = (end_time - start_time).total_seconds() / 60

    # Save results
    output = {
        "metadata": {
            "timestamp": end_time.isoformat(),
            "experiment": "ensemble_diversity_scaling",
            "hypothesis": "Parallel diversity > serial optimization",
            "configuration": "Simple agents (tools_only), seed variation only",
            "time_per_agent": time_per_agent,
            "max_parallel": max_parallel,
            "fully_concurrent": True,
            "total_agents": total_agents,
            "wall_time_minutes": round(elapsed, 2),
        },
        "results": all_results,
    }

    output_path = repo_root / "ensemble_diversity_scaling_results.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)

    # Print summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"\n{'N Agents':<12s} {'Unique Types':<15s} {'Real Attacks':<15s} {'Attack Types':<30s}")
    print("-" * 70)

    for r in all_results:
        n = r["n_agents"]
        types = r["combined"]["num_unique_types"]
        attacks = r["combined"]["real_attacks"]
        type_list = (
            ", ".join(r["combined"]["attack_types"]) if r["combined"]["attack_types"] else "none"
        )
        print(f"{n:<12d} {types:<15d} {attacks:<15d} {type_list:<30s}")

    print("-" * 70)

    # Analyze scaling
    if len(all_results) >= 2:
        n1_types = all_results[0]["combined"]["num_unique_types"]
        n100_types = all_results[-1]["combined"]["num_unique_types"]

        if n100_types > n1_types:
            improvement = ((n100_types - n1_types) / max(n1_types, 1)) * 100
            print(f"\n✓ Diversity improves with ensemble size:")
            print(f"  N=1: {n1_types} types → N={all_results[-1]['n_agents']}: {n100_types} types")
            print(f"  Improvement: +{improvement:.0f}%")
            print("\n  Conclusion: Parallel Diversity > Serial Optimization")
        else:
            print(f"\n✗ No diversity improvement observed")
            print(f"  N=1: {n1_types} types, N={all_results[-1]['n_agents']}: {n100_types} types")

    print(f"\n💾 Detailed results saved to: {output_path}")
    print(f"⏱️  Actual wall time: {elapsed:.1f} minutes")
    print(f"✅ Experiment complete at {datetime.now().strftime('%H:%M:%S')}\n")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
