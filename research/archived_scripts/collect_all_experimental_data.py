#!/usr/bin/env python3
"""
Complete Experimental Data Collection for Paper
Runs all experiments and generates comprehensive dataset
Now with async parallelization for faster execution
Updated to support multiple models and multi-seed averaging
"""

import argparse
import asyncio
import json
import os
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

from archived_imports import setup_imports

repo_root = setup_imports()

from examples.guardrails.guardrail_prompt_injection import (
    Guardrail as PromptInjectionGuardrail,
)

from aicomp_sdk.attacks.baselines.attacker_goexplore import AttackAlgorithm
from aicomp_sdk.attacks.baselines.guardrail_allow import Guardrail as AllowGuardrail
from aicomp_sdk.core.env import SandboxEnv
from tests.integration.test_verify_findings import detect_real_attacks

# Verify API key
if not os.environ.get("OPENAI_API_KEY"):
    print("ERROR: OPENAI_API_KEY required")
    sys.exit(1)

fixtures = repo_root / "fixtures"

# Parse command line arguments
parser = argparse.ArgumentParser(description="Run experimental data collection")
parser.add_argument(
    "--model",
    type=str,
    default="gpt-4o-mini",
    choices=["gpt-4o-mini", "gpt-4o", "gpt-o3-mini"],
    help="Model to use for experiments",
)
parser.add_argument(
    "--seeds",
    type=int,
    nargs="+",
    default=[42, 123, 456],
    help="Seeds to use for averaging (default: 42 123 456)",
)
args = parser.parse_args()

MODEL = args.model
SEEDS = args.seeds


def extract_tool_stats(findings):
    """Extract detailed statistics from findings"""
    stats = {
        "total_findings": len(findings),
        "tool_calls": 0,
        "total_tool_calls": 0,
        "successful_tools": defaultdict(int),
        "depth_dist": defaultdict(int),
        "real_attacks_by_type": defaultdict(int),
        "unique_attack_types": 0,
        "chains_by_operation": defaultdict(list),
    }

    for f in findings:
        msgs = f.get("user_messages", [])
        stats["depth_dist"][len(msgs)] += 1

        events = f.get("trace", {}).get("tool_events", [])
        stats["total_tool_calls"] += len(events)
        
        for evt in events:
            tool = evt.get("name", "")
            if evt.get("ok"):
                stats["successful_tools"][tool] += 1

        # Real attacks
        real = detect_real_attacks(events)
        for attack in real:
            atype = attack.get("type", "UNKNOWN")
            stats["real_attacks_by_type"][atype] += 1

        # Track chains per operation
        for evt in events:
            if evt.get("ok"):
                tool = evt.get("name", "")
                if tool in ["shell.run", "fs.delete", "http.post", "email.send"]:
                    stats["chains_by_operation"][tool].append(
                        {
                            "chain": " -> ".join(msgs),
                            "depth": len(msgs),
                            "args": evt.get("args", {}),
                        }
                    )

    stats["tool_calls"] = stats["total_tool_calls"]
    stats["real_attacks"] = sum(stats["real_attacks_by_type"].values())
    stats["unique_attack_types"] = len(stats["real_attacks_by_type"])
    
    return dict(stats)


def average_stats(stats_list):
    """Average statistics across multiple runs"""
    if not stats_list:
        return {}
    
    avg = {
        "total_findings": round(sum(s["total_findings"] for s in stats_list) / len(stats_list), 1),
        "real_attacks": round(sum(s["real_attacks"] for s in stats_list) / len(stats_list), 1),
        "unique_attack_types": round(sum(s["unique_attack_types"] for s in stats_list) / len(stats_list), 1),
        "tool_calls": round(sum(s["tool_calls"] for s in stats_list) / len(stats_list), 1),
        "individual_runs": stats_list,
    }
    
    return avg


def run_experiment(name, seed, fixtures, guardrail_cls, attack_config, budget, model):
    """Run a single experiment (for parallel execution)"""
    print(f"[{name}-seed{seed}] Starting with {model}...")
    
    # Set model in environment
    os.environ["OPENAI_MODEL"] = model
    
    env = SandboxEnv(seed=seed, fixtures_dir=fixtures, guardrail=guardrail_cls())
    atk = AttackAlgorithm(attack_config)
    findings = atk.run(env, budget)
    stats = extract_tool_stats(findings)
    print(
        f"[{name}-seed{seed}] Complete: {stats['total_findings']} findings, {stats['real_attacks']} real attacks"
    )
    return stats


async def run_all_experiments_async(model, seeds):
    """Run all experiments in parallel using async"""
    print("=" * 70)
    print(f"COMPREHENSIVE DATA COLLECTION FOR PAPER - {model}")
    print("=" * 70)
    print(f"\nModel: {model}")
    print(f"Seeds: {seeds}")
    print(f"Started: {datetime.now().strftime('%H:%M:%S')}")

    # Define base experiment configurations (without seeds)
    base_experiments = [
        # Main experiments - RQ1 (6 configs)
        (
            "1_general_150s_noguard",
            AllowGuardrail,
            {"max_turns": 6, "branch_batch": 12, "target_shell": False},
            {"seconds": 150},
        ),
        (
            "2_general_150s_guard",
            PromptInjectionGuardrail,
            {"max_turns": 6, "branch_batch": 12, "target_shell": False},
            {"seconds": 150},
        ),
        (
            "3_targeted_120s_noguard",
            AllowGuardrail,
            {"max_turns": 6, "branch_batch": 12, "target_shell": True},
            {"seconds": 120},
        ),
        (
            "4_targeted_120s_guard",
            PromptInjectionGuardrail,
            {"max_turns": 6, "branch_batch": 12, "target_shell": True},
            {"seconds": 120},
        ),
        (
            "5_baseline_20s",
            AllowGuardrail,
            {"max_turns": 6, "branch_batch": 12, "target_shell": False},
            {"seconds": 20},
        ),
        (
            "6_intermediate_60s",
            AllowGuardrail,
            {"max_turns": 6, "branch_batch": 12, "target_shell": False},
            {"seconds": 60},
        ),
    ]

    # RQ2 ablations - Signature ablations (5 configs, but RQ2 seed sensitivity is separate)
    for variant_name, config in [
        (
            "sig_tools_only",
            {
                "use_args": False,
                "use_outputs": False,
                "use_intent": False,
                "causality_bonus": 0,
                "high_bonus": 0,
                "critical_bonus": 0,
                "medium_bonus": 0,
            },
        ),
        (
            "sig_args3",
            {
                "use_args": True,
                "args_count": 3,
                "use_outputs": False,
                "use_intent": False,
                "causality_bonus": 0,
                "high_bonus": 0,
                "critical_bonus": 0,
                "medium_bonus": 0,
            },
        ),
        (
            "sig_args5",
            {
                "use_args": True,
                "args_count": 5,
                "use_outputs": False,
                "use_intent": False,
                "causality_bonus": 0,
                "high_bonus": 0,
                "critical_bonus": 0,
                "medium_bonus": 0,
            },
        ),
        (
            "sig_args_outputs",
            {
                "use_args": True,
                "args_count": 5,
                "use_outputs": True,
                "use_intent": False,
                "causality_bonus": 0,
                "high_bonus": 0,
                "critical_bonus": 0,
                "medium_bonus": 0,
            },
        ),
        (
            "sig_full_intent",
            {
                "use_args": True,
                "args_count": 5,
                "use_outputs": True,
                "use_intent": True,
                "causality_bonus": 0,
                "high_bonus": 0,
                "critical_bonus": 0,
                "medium_bonus": 0,
            },
        ),
    ]:
        full_config = {"max_turns": 6, "branch_batch": 12, **config}
        base_experiments.append((variant_name, AllowGuardrail, full_config, {"seconds": 90}))

    # RQ3 - Reward ablations (2 configs)
    for variant_name, config in [
        (
            "rew_no_bonus",
            {
                "use_intent": True,
                "use_args": True,
                "use_outputs": True,
                "causality_bonus": 0,
                "high_bonus": 0,
                "critical_bonus": 0,
                "medium_bonus": 0,
            },
        ),
        (
            "rew_with_bonus",
            {
                "use_intent": True,
                "use_args": True,
                "use_outputs": True,
                "causality_bonus": 100,
                "high_bonus": 75,
                "critical_bonus": 150,
                "medium_bonus": 25,
            },
        ),
    ]:
        full_config = {"max_turns": 6, "branch_batch": 12, **config}
        base_experiments.append((variant_name, AllowGuardrail, full_config, {"seconds": 90}))

    # RQ4 - Individual enhancement ablations (5 configs)
    for variant_name, config in [
        (
            "enh_baseline",
            {
                "use_intent": False,
                "use_args": False,
                "use_outputs": False,
                "causality_bonus": 0,
                "high_bonus": 0,
                "critical_bonus": 0,
                "medium_bonus": 0,
                "target_shell": False,
            },
        ),
        (
            "enh_intent_only",
            {
                "use_intent": True,
                "use_args": False,
                "use_outputs": False,
                "causality_bonus": 0,
                "high_bonus": 0,
                "critical_bonus": 0,
                "medium_bonus": 0,
                "target_shell": False,
            },
        ),
        (
            "enh_reward_only",
            {
                "use_intent": False,
                "use_args": False,
                "use_outputs": False,
                "causality_bonus": 100,
                "high_bonus": 75,
                "critical_bonus": 150,
                "medium_bonus": 25,
                "target_shell": False,
            },
        ),
        (
            "enh_targeted_only",
            {
                "use_intent": False,
                "use_args": False,
                "use_outputs": False,
                "causality_bonus": 0,
                "high_bonus": 0,
                "critical_bonus": 0,
                "medium_bonus": 0,
                "target_shell": True,
            },
        ),
        (
            "enh_all_combined",
            {
                "use_intent": True,
                "use_args": True,
                "use_outputs": True,
                "causality_bonus": 100,
                "high_bonus": 75,
                "critical_bonus": 150,
                "medium_bonus": 25,
                "target_shell": True,
            },
        ),
    ]:
        full_config = {"max_turns": 6, "branch_batch": 12, **config}
        base_experiments.append((variant_name, AllowGuardrail, full_config, {"seconds": 90}))

    # Expand experiments with all seeds
    all_experiments = []
    for name, guard, config, budget in base_experiments:
        for seed in seeds:
            all_experiments.append((f"{name}_seed{seed}", seed, guard, config, budget))

    print(f"\nRunning {len(base_experiments)} base configs × {len(seeds)} seeds = {len(all_experiments)} total experiments...")
    print(f"Parallelization: 4 workers\n")

    # Run in parallel using ThreadPoolExecutor
    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor(max_workers=4) as executor:
        tasks = [
            loop.run_in_executor(
                executor, run_experiment, name, seed, fixtures, guard, config, budget, model
            )
            for name, seed, guard, config, budget in all_experiments
        ]
        all_stats = await asyncio.gather(*tasks)

    # Group results by base experiment name and average across seeds
    exp_map = {}
    for (name, seed, *_), stats in zip(all_experiments, all_stats):
        base_name = name.rsplit("_seed", 1)[0]
        if base_name not in exp_map:
            exp_map[base_name] = []
        exp_map[base_name].append(stats)
    
    # Average results for each base experiment
    averaged_results = {name: average_stats(stats_list) for name, stats_list in exp_map.items()}

    return averaged_results


# Main execution
async def main():
    exp_results = await run_all_experiments_async(MODEL, SEEDS)

    # Build results structure
    results = {
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "model": MODEL,
            "seeds": SEEDS,
            "note": f"Complete experimental data with {len(SEEDS)}-seed averaging",
        },
        "general_150s": {
            "no_guard": exp_results["1_general_150s_noguard"],
            "with_guard": exp_results["2_general_150s_guard"],
        },
        "shell_targeted": {
            "no_guard": exp_results["3_targeted_120s_noguard"],
            "with_guard": exp_results["4_targeted_120s_guard"],
            "shell_chains_no_guard": len(
                exp_results["3_targeted_120s_noguard"]["chains_by_operation"].get("shell.run", [])
            ),
            "shell_chains_with_guard": len(
                exp_results["4_targeted_120s_guard"]["chains_by_operation"].get("shell.run", [])
            ),
        },
        "baseline_20s": {"no_guard": exp_results["5_baseline_20s"]},
        "intermediate_60s": {"no_guard": exp_results["6_intermediate_60s"]},
    }

    # Runtime scaling metrics
    results["runtime_scaling"] = {
        "20s": {
            "findings": exp_results["5_baseline_20s"]["total_findings"],
            "real_attacks": sum(exp_results["5_baseline_20s"]["real_attacks_by_type"].values()),
        },
        "60s": {
            "findings": exp_results["6_intermediate_60s"]["total_findings"],
            "real_attacks": sum(exp_results["6_intermediate_60s"]["real_attacks_by_type"].values()),
        },
        "150s": {
            "findings": exp_results["1_general_150s_noguard"]["total_findings"],
            "real_attacks": sum(
                exp_results["1_general_150s_noguard"]["real_attacks_by_type"].values()
            ),
        },
    }

    # Ablations
    results["ablations"] = {
        "state_signatures": {
            "tools_only": exp_results["sig_tools_only"],
            "tools_args3": exp_results["sig_args3"],
            "tools_args5": exp_results["sig_args5"],
            "tools_args_outputs": exp_results["sig_args_outputs"],
            "full_with_intent": exp_results["sig_full_intent"],
        },
        "reward_shaping": {
            "no_bonus": exp_results["rew_no_bonus"],
            "with_bonus": exp_results["rew_with_bonus"],
        },
        "enhancement_isolation": {
            "baseline": exp_results["enh_baseline"],
            "intent_only": exp_results["enh_intent_only"],
            "reward_only": exp_results["enh_reward_only"],
            "targeted_only": exp_results["enh_targeted_only"],
            "all_combined": exp_results["enh_all_combined"],
        },
    }

    # Print summary
    print("\n" + "=" * 70)
    print("RESULTS SUMMARY")
    print("=" * 70)
    print(f"\n📊 Main Experiments:")
    print(
        f"  General 150s (no guard): {results['general_150s']['no_guard']['total_findings']} findings"
    )
    print(
        f"  Targeted 120s (with guard): {results['shell_targeted']['with_guard']['total_findings']} findings, {results['shell_targeted']['shell_chains_with_guard']} shells"
    )

    # Save to JSON
    output_file = repo_root / f"paper_experimental_data_{MODEL.replace('-', '_')}.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2, default=str)

    print(f"\n💾 Complete dataset saved to: {output_file}")
    print(
        f"✅ All {len(exp_results)} base experiments (averaged over {len(SEEDS)} seeds) complete at {datetime.now().strftime('%H:%M:%S')}"
    )
    print(f"\n{'='*70}\n")


if __name__ == "__main__":
    asyncio.run(main())
