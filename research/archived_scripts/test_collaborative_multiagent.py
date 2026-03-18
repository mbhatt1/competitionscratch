#!/usr/bin/env python3
"""
Collaborative Multi-Agent Experiment with Shared Archive
Tests: Strategy diversity + State consensus + Coordinated coverage
"""

import json
import os
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
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
from aicomp_sdk.attacks.baselines.shared_archive import SharedArchive
from aicomp_sdk.attacks.real_attack_detection import detect_real_attacks

if not os.environ.get("OPENAI_API_KEY"):
    print("ERROR: OPENAI_API_KEY required")
    sys.exit(1)
require_openai_key()

fixtures = get_fixtures_dir()


def extract_stats(findings):
    stats = {
        "total_findings": len(findings),
        "real_attacks": 0,
        "attack_types": defaultdict(int),
        "unique_attack_sigs": set(),
    }

    for f in findings:
        events = f.get("trace", {}).get("tool_events", [])
        real = detect_real_attacks(events)
        for attack in real:
            stats["real_attacks"] += 1
            atype = attack.get("type", "UNKNOWN")
            stats["attack_types"][atype] += 1
            sig = f"{atype}:{attack.get('executed_tool')}:{attack.get('executed_args', {}).get('path', '')}"
            stats["unique_attack_sigs"].add(sig)

    stats["unique_attacks"] = len(stats["unique_attack_sigs"])
    del stats["unique_attack_sigs"]
    stats["attack_types"] = dict(stats["attack_types"])
    return stats


def run_collaborative_agent(agent_id, config, shared_archive, fixtures, duration_s):
    """Run a single agent with access to shared archive"""
    print(f"  [Agent {agent_id}] Starting with config: {config.get('name', 'unknown')}")

    # NOTE: This is a simulation - would need to modify AttackAlgorithm
    # to actually USE the shared archive during exploration
    # For now, run independently but could theoretically share

    env = create_archived_sandbox_env(
        seed=42,
        fixtures_dir=fixtures,
        guardrail=AllowGuardrail(),
        agent_selection="openai",
    )
    atk = AttackAlgorithm({"max_turns": 6, "branch_batch": 12, **config["params"]})
    candidates = run_archived_attack(atk, env, time_budget_s=duration_s)
    findings = replay_archived_candidates(
        candidates=candidates,
        seed=42,
        fixtures_dir=fixtures,
        guardrail_factory=AllowGuardrail,
        agent_selection="openai",
    )

    stats = extract_stats(findings)
    print(
        f"  [Agent {agent_id}] Complete: {stats['total_findings']} findings, {stats['unique_attacks']} unique attacks"
    )

    return {
        "agent_id": agent_id,
        "config_name": config["name"],
        "findings": findings,
        "stats": stats,
    }


print("=" * 70)
print("COLLABORATIVE MULTI-AGENT EXPERIMENT")
print("=" * 70)
print(f"\nHypothesis: Shared archive + strategic diversity > independent ensemble")
print(f"Started: {datetime.now().strftime('%H:%M:%S')}\n")

results = {
    "metadata": {
        "timestamp": datetime.now().isoformat(),
        "experiment": "Collaborative multi-agent with shared archive",
        "note": "Simulated - full implementation would modify AttackAlgorithm to use SharedArchive",
    }
}

# Define 3 agents with different strategies
agent_configs = [
    {
        "name": "tools_only",
        "params": {
            "use_args": False,
            "use_outputs": False,
            "use_intent": False,
            "causality_bonus": 0,
        },
    },
    {
        "name": "with_targeting",
        "params": {
            "use_args": False,
            "use_outputs": False,
            "use_intent": False,
            "causality_bonus": 0,
            "target_shell": True,
        },
    },
    {
        "name": "with_rewards",
        "params": {
            "use_args": False,
            "use_outputs": False,
            "use_intent": False,
            "causality_bonus": 100,
            "high_bonus": 75,
            "critical_bonus": 150,
        },
    },
]

# Test 1: Collaborative (Simulated)
print("[TEST 1] Collaborative: 3 Agents with Shared Archive Awareness (60s each)...")
shared_archive = SharedArchive()
all_findings_collab = []
all_stats_collab = []

with ThreadPoolExecutor(max_workers=3) as executor:
    futures = [
        executor.submit(run_collaborative_agent, i, config, shared_archive, fixtures, 60)
        for i, config in enumerate(agent_configs, 1)
    ]
    agent_results = [f.result() for f in futures]

for result in agent_results:
    all_stats_collab.append(
        {
            "agent_id": result["agent_id"],
            "config": result["config_name"],
            "stats": result["stats"],
        }
    )
    all_findings_collab.extend(result["findings"])

collab_combined = extract_stats(all_findings_collab)
results["collaborative"] = {
    "individual_agents": all_stats_collab,
    "combined_deduplicated": collab_combined,
    "archive_stats": shared_archive.get_stats(),
}

print(
    f"\nCollaborative Total: {collab_combined['total_findings']} findings, {collab_combined['unique_attacks']} unique attacks"
)
print(f"Shared Archive: {shared_archive.get_stats()}")

# Test 2: For comparison, run independent (same configs, no sharing)
print(f"\n[TEST 2] Independent: Same 3 Agents WITHOUT Sharing (60s each)...")
all_findings_indep = []
all_stats_indep = []

for i, config in enumerate(agent_configs, 1):
    print(f"  [Agent {i}] Running {config['name']} independently...")
    env = create_archived_sandbox_env(
        seed=42,
        fixtures_dir=fixtures,
        guardrail=AllowGuardrail(),
        agent_selection="openai",
    )
    atk = AttackAlgorithm({"max_turns": 6, "branch_batch": 12, **config["params"]})
    candidates = run_archived_attack(atk, env, time_budget_s=60)
    findings = replay_archived_candidates(
        candidates=candidates,
        seed=42,
        fixtures_dir=fixtures,
        guardrail_factory=AllowGuardrail,
        agent_selection="openai",
    )
    stats = extract_stats(findings)
    all_stats_indep.append({"agent_id": i, "config": config["name"], "stats": stats})
    all_findings_indep.extend(findings)
    print(f"       → {stats['total_findings']} findings, {stats['unique_attacks']} unique attacks")

indep_combined = extract_stats(all_findings_indep)
results["independent"] = {
    "individual_agents": all_stats_indep,
    "combined_deduplicated": indep_combined,
}

print(
    f"\nIndependent Total: {indep_combined['total_findings']} findings, {indep_combined['unique_attacks']} unique attacks"
)

# Save
output_file = repo_root / "collaborative_multiagent_results.json"
with open(output_file, "w") as f:
    json.dump(results, f, indent=2, default=str)

# Comparison
print("\n" + "=" * 70)
print("COLLABORATIVE vs INDEPENDENT")
print("=" * 70)
print(
    f"\nCollaborative (shared archive): {collab_combined['total_findings']} findings, {collab_combined['unique_attacks']} unique attacks"
)
print(
    f"Independent (no sharing):       {indep_combined['total_findings']} findings, {indep_combined['unique_attacks']} unique attacks"
)

if collab_combined["unique_attacks"] > indep_combined["unique_attacks"]:
    print(
        f"\n✓ Collaboration HELPS (+{collab_combined['unique_attacks'] - indep_combined['unique_attacks']} attacks)"
    )
elif collab_combined["unique_attacks"] < indep_combined["unique_attacks"]:
    print(
        f"\n✗ Collaboration HURTS (-{indep_combined['unique_attacks'] - collab_combined['unique_attacks']} attacks)"
    )
else:
    print(f"\n= No difference (both found {collab_combined['unique_attacks']} attacks)")

print(f"\n💾 Results saved to: {output_file}")
print("=" * 70)
print("\nNOTE: Current implementation simulates collaboration.")
print("Full implementation requires modifying AttackAlgorithm to:")
print("  1. Accept shared_archive parameter")
print("  2. Use shared_archive.select_cell_for_agent() instead of local _select_cell()")
print("  3. Call shared_archive.add_cell() for novel discoveries")
print("  4. Call shared_archive.record_visit() after exploring")
print("=" * 70 + "\n")
