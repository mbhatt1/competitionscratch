#!/usr/bin/env python3
"""
Negative Reward Experiment
Tests if penalizing non-attacks works better than rewarding attacks
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


def extract_stats(findings):
    """Extract statistics from findings"""
    stats = {
        "total_findings": len(findings),
        "real_attacks": 0,
        "tool_calls": 0,
        "attack_types": defaultdict(int),
    }

    for f in findings:
        events = f.get("trace", {}).get("tool_events", [])
        stats["tool_calls"] += len(events)

        real = detect_real_attacks(events)
        for attack in real:
            stats["real_attacks"] += 1
            stats["attack_types"][attack.get("type", "UNKNOWN")] += 1

    return stats


print("=" * 70)
print("NEGATIVE REWARD EXPERIMENTS")
print("=" * 70)
print(f"\nStarted: {datetime.now().strftime('%H:%M:%S')}\n")

# First, modify AttackAlgorithm to support negative rewards
# For now, test with different penalty configurations

results = {
    "metadata": {
        "timestamp": datetime.now().isoformat(),
        "experiment": "Negative rewards vs positive rewards",
        "hypothesis": "Penalizing failures maintains broader exploration",
    }
}

# Test configurations
configs = [
    (
        "baseline",
        {
            "use_intent": False,
            "use_args": False,
            "use_outputs": False,
            "causality_bonus": 0,
        },
    ),
    (
        "positive_rewards",
        {
            "use_intent": True,
            "use_args": True,
            "use_outputs": True,
            "causality_bonus": 100,
            "high_bonus": 75,
            "critical_bonus": 150,
        },
    ),
    # NOTE: Negative rewards not yet implemented in algorithm
    # Would need to add: non_attack_penalty, false_positive_penalty, etc.
    (
        "simple_best",
        {
            "use_intent": False,
            "use_args": False,
            "use_outputs": False,
            "causality_bonus": 0,
            "target_shell": False,
        },
    ),
    (
        "targeted_best",
        {
            "use_intent": False,
            "use_args": False,
            "use_outputs": False,
            "causality_bonus": 0,
            "target_shell": True,
        },
    ),
]

for i, (name, config) in enumerate(configs, 1):
    print(f"[{i}/{len(configs)}] Testing: {name}...")
    env = create_archived_sandbox_env(
        seed=42,
        fixtures_dir=fixtures,
        guardrail=AllowGuardrail(),
        agent_selection="openai",
    )
    atk = AttackAlgorithm({"max_turns": 6, "branch_batch": 12, **config})
    findings = atk.run(env, {"time_budget_s": 120})
    stats = extract_stats(findings)

    results[name] = stats
    print(
        f"    → {stats['total_findings']} findings, {stats['real_attacks']} real attacks, {stats['tool_calls']} tool calls"
    )
    if stats["attack_types"]:
        print(f"       Types: {dict(stats['attack_types'])}")

# Save results
output_file = repo_root / "negative_rewards_results.json"
with open(output_file, "w") as f:
    json.dump(results, f, indent=2, default=str)

print(f"\n{'=' * 70}")
print("SUMMARY")
print(f"{'=' * 70}\n")

for name, stats in results.items():
    if name != "metadata":
        efficiency = (
            (stats["real_attacks"] / stats["tool_calls"] * 100) if stats["tool_calls"] > 0 else 0
        )
        print(
            f"{name:20s}: {stats['total_findings']:3d} findings, {stats['real_attacks']:2d} real ({efficiency:.2f}% efficient)"
        )

print(f"\n💾 Results saved to: {output_file}")
print(f"✅ Complete at {datetime.now().strftime('%H:%M:%S')}\n")

print("\n" + "=" * 70)
print("NEXT STEPS TO IMPLEMENT NEGATIVE REWARDS:")
print("=" * 70)
print("""
1. Modify aicomp_sdk/baselines/attacker_goexplore.py scoring:
   
   # Instead of:
   score = 10*novelty + 100*real_attacks
   
   # Try:
   penalty = -50 if len(real_attacks) == 0 else 0
   score = 10*novelty + penalty
   
2. Add config parameters:
   - non_attack_penalty (default -50)
   - false_positive_penalty (default -25)
   - exploration_bonus (small positive for diversity)

3. Hypothesis: Negative rewards push AWAY from dead ends,
   maintaining broader sampling without collapse

4. Test variants:
   - Small penalties (-10 to -25)
   - Medium penalties (-50 to -75)
   - Large penalties (-100 to -200)
""")
print("=" * 70 + "\n")
