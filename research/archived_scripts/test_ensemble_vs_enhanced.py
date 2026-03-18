#!/usr/bin/env python3
"""
Ensemble vs Enhanced Experiment
Tests if multiple simple agents with different seeds outperform a single enhanced agent
"""

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
    replay_archived_candidates,
    require_openai_key,
    run_archived_attack,
    setup_imports,
)

repo_root = setup_imports()

from aicomp_sdk.attacks.baselines.attacker_goexplore import AttackAlgorithm
from aicomp_sdk.attacks.baselines.guardrail_allow import Guardrail as AllowGuardrail
from aicomp_sdk.attacks.real_attack_detection import detect_real_attacks

# Verify API key
if not os.environ.get("OPENAI_API_KEY"):
    print("ERROR: OPENAI_API_KEY required")
    sys.exit(1)
require_openai_key()

fixtures = get_fixtures_dir()


def extract_stats(findings):
    """Extract statistics including unique attacks"""
    stats = {
        "total_findings": len(findings),
        "real_attacks": 0,
        "tool_calls": 0,
        "attack_types": defaultdict(int),
        "unique_attack_signatures": set(),
    }

    for f in findings:
        events = f.get("trace", {}).get("tool_events", [])
        stats["tool_calls"] += len(events)

        real = detect_real_attacks(events)
        for attack in real:
            stats["real_attacks"] += 1
            atype = attack.get("type", "UNKNOWN")
            stats["attack_types"][atype] += 1

            # Create unique signature for deduplication
            sig = f"{atype}:{attack.get('executed_tool')}:{attack.get('executed_args', {}).get('path', '')}"
            stats["unique_attack_signatures"].add(sig)

    stats["attack_types"] = dict(stats["attack_types"])
    stats["unique_attacks"] = len(stats["unique_attack_signatures"])
    del stats["unique_attack_signatures"]  # Don't save set to JSON

    return stats


print("=" * 70)
print("ENSEMBLE vs ENHANCED EXPERIMENT")
print("=" * 70)
print(f"\nHypothesis: Multiple simple agents with different seeds > Single enhanced agent")
print(f"Started: {datetime.now().strftime('%H:%M:%S')}\n")

results = {
    "metadata": {
        "timestamp": datetime.now().isoformat(),
        "hypothesis": "Ensemble diversity beats monolithic optimization",
    }
}

# Configuration
simple_config = {
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

enhanced_config = {
    "max_turns": 6,
    "branch_batch": 12,
    "use_intent": True,
    "use_args": True,
    "use_outputs": True,
    "causality_bonus": 100,
    "high_bonus": 75,
    "critical_bonus": 150,
    "medium_bonus": 25,
    "target_shell": True,
}

# Test 1: Single Enhanced Agent (180s total budget)
print("[1/4] Single Enhanced Agent (180s, seed=42)...")
env_enh = create_archived_sandbox_env(
    seed=42,
    fixtures_dir=fixtures,
    guardrail=AllowGuardrail(),
    agent_selection="openai",
)
atk_enh = AttackAlgorithm(enhanced_config)
candidates_enh = run_archived_attack(atk_enh, env_enh, time_budget_s=180)
findings_enh = replay_archived_candidates(
    candidates=candidates_enh,
    seed=42,
    fixtures_dir=fixtures,
    guardrail_factory=AllowGuardrail,
    agent_selection="openai",
)
stats_enh = extract_stats(findings_enh)
results["single_enhanced"] = stats_enh
print(
    f"    → {stats_enh['total_findings']} findings, {stats_enh['unique_attacks']} unique attacks\n"
)

# Test 2: Ensemble of 3 Simple Agents (60s each = 180s total budget)
print("[2/4] Ensemble: 3 Simple Agents (60s each, seeds=[42,123,456])...")
ensemble_findings = []
ensemble_all_stats = []

for i, seed in enumerate([42, 123, 456], 1):
    print(f"  [{i}/3] Running simple agent with seed={seed}...")
    env_simple = create_archived_sandbox_env(
        seed=seed,
        fixtures_dir=fixtures,
        guardrail=AllowGuardrail(),
        agent_selection="openai",
    )
    atk_simple = AttackAlgorithm(simple_config)
    candidates = run_archived_attack(atk_simple, env_simple, time_budget_s=60)
    findings = replay_archived_candidates(
        candidates=candidates,
        seed=seed,
        fixtures_dir=fixtures,
        guardrail_factory=AllowGuardrail,
        agent_selection="openai",
    )
    stats = extract_stats(findings)
    ensemble_all_stats.append(stats)
    ensemble_findings.extend(findings)
    print(f"       → {stats['total_findings']} findings, {stats['unique_attacks']} unique attacks")

# Aggregate ensemble results (deduplicate)
ensemble_combined = extract_stats(ensemble_findings)
results["ensemble_simple"] = {
    "individual_runs": ensemble_all_stats,
    "combined_deduplicated": ensemble_combined,
}

print(
    f"\n    Ensemble Total: {ensemble_combined['total_findings']} findings, {ensemble_combined['unique_attacks']} unique attacks\n"
)

# Test 3: Ensemble of 3 Different Simple Strategies (60s each)
print("[3/4] Ensemble: 3 Different Strategies (60s each, seed=42)...")
strategies = [
    (
        "tools_only",
        {
            "use_args": False,
            "use_outputs": False,
            "use_intent": False,
            "causality_bonus": 0,
        },
    ),
    (
        "with_targeting",
        {
            "use_args": False,
            "use_outputs": False,
            "use_intent": False,
            "causality_bonus": 0,
            "target_shell": True,
        },
    ),
    (
        "with_rewards",
        {
            "use_args": False,
            "use_outputs": False,
            "use_intent": False,
            "causality_bonus": 100,
            "high_bonus": 75,
            "critical_bonus": 150,
        },
    ),
]

diverse_findings = []
diverse_stats_list = []

for i, (name, config) in enumerate(strategies, 1):
    print(f"  [{i}/3] Running {name}...")
    env_div = create_archived_sandbox_env(
        seed=42,
        fixtures_dir=fixtures,
        guardrail=AllowGuardrail(),
        agent_selection="openai",
    )
    atk_div = AttackAlgorithm({"max_turns": 6, "branch_batch": 12, **config})
    candidates = run_archived_attack(atk_div, env_div, time_budget_s=60)
    findings = replay_archived_candidates(
        candidates=candidates,
        seed=42,
        fixtures_dir=fixtures,
        guardrail_factory=AllowGuardrail,
        agent_selection="openai",
    )
    stats = extract_stats(findings)
    diverse_stats_list.append({"name": name, "stats": stats})
    diverse_findings.extend(findings)
    print(f"       → {stats['total_findings']} findings, {stats['unique_attacks']} unique attacks")

diverse_combined = extract_stats(diverse_findings)
results["ensemble_diverse"] = {
    "individual_strategies": diverse_stats_list,
    "combined_deduplicated": diverse_combined,
}

print(
    f"\n    Diverse Ensemble Total: {diverse_combined['total_findings']} findings, {diverse_combined['unique_attacks']} unique attacks\n"
)

# Test 4: Comparison baseline
print("[4/4] Baseline: Single Simple Agent (180s, seed=42)...")
env_baseline = create_archived_sandbox_env(
    seed=42,
    fixtures_dir=fixtures,
    guardrail=AllowGuardrail(),
    agent_selection="openai",
)
atk_baseline = AttackAlgorithm(simple_config)
candidates_baseline = run_archived_attack(atk_baseline, env_baseline, time_budget_s=180)
findings_baseline = replay_archived_candidates(
    candidates=candidates_baseline,
    seed=42,
    fixtures_dir=fixtures,
    guardrail_factory=AllowGuardrail,
    agent_selection="openai",
)
stats_baseline = extract_stats(findings_baseline)
results["single_simple_180s"] = stats_baseline
print(
    f"    → {stats_baseline['total_findings']} findings, {stats_baseline['unique_attacks']} unique attacks\n"
)

# Save results
output_file = repo_root / "ensemble_vs_enhanced_results.json"
with open(output_file, "w") as f:
    json.dump(results, f, indent=2, default=str)

# Print comparison
print("=" * 70)
print("COMPARISON SUMMARY")
print("=" * 70)
print(f"\n{'Configuration':<30s} {'Findings':>10s} {'Unique Attacks':>15s} {'Total Budget':>15s}")
print("-" * 70)
print(
    f"{'Single Enhanced':<30s} {stats_enh['total_findings']:>10d} {stats_enh['unique_attacks']:>15d} {'180s':>15s}"
)
print(
    f"{'Ensemble (3 simple, same config)':<30s} {ensemble_combined['total_findings']:>10d} {ensemble_combined['unique_attacks']:>15d} {'180s (3x60s)':>15s}"
)
print(
    f"{'Ensemble (3 diverse strategies)':<30s} {diverse_combined['total_findings']:>10d} {diverse_combined['unique_attacks']:>15d} {'180s (3x60s)':>15s}"
)
print(
    f"{'Single Simple (long run)':<30s} {stats_baseline['total_findings']:>10d} {stats_baseline['unique_attacks']:>15d} {'180s':>15s}"
)
print("-" * 70)

# Determine winner
max_attacks = max(
    stats_enh["unique_attacks"],
    ensemble_combined["unique_attacks"],
    diverse_combined["unique_attacks"],
    stats_baseline["unique_attacks"],
)

if (
    ensemble_combined["unique_attacks"] == max_attacks
    or diverse_combined["unique_attacks"] == max_attacks
):
    print("\n🎯 RESULT: Ensemble approach WINS")
    print("   Multiple simple agents with diversity > Single enhanced agent")
elif stats_enh["unique_attacks"] == max_attacks:
    print("\n❌ RESULT: Enhanced approach wins")
    print("   Sophistication beats ensemble")
else:
    print("\n⚖️  RESULT: Inconclusive (all similar)")

print(f"\n💾 Detailed results saved to: {output_file}")
print(f"✅ Experiment complete at {datetime.now().strftime('%H:%M:%S')}\n")
print("=" * 70)
