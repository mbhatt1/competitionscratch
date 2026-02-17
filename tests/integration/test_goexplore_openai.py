#!/usr/bin/env python3
"""
Test Go-Explore attack with OpenAI API
"""

import os
from pathlib import Path

# Import the baseline Go-Explore attacker
from aicomp_sdk.attacks.baselines.attacker_goexplore import AttackAlgorithm
from aicomp_sdk.attacks.baselines.guardrail_allow import Guardrail
from aicomp_sdk.core.env import SandboxEnv

print("=" * 70)
print("Testing Go-Explore Attack with OpenAI API")
print("=" * 70)

if not os.environ.get("OPENAI_API_KEY"):
    print("\n⚠️  OPENAI_API_KEY not set")
    print("   Will use deterministic fallback\n")
else:
    print("\n✓ OPENAI_API_KEY found\n")

# Setup - fixtures are in the project root
fixtures = Path(__file__).parent.parent.parent / "fixtures"
env = SandboxEnv(seed=42, fixtures_dir=fixtures, guardrail=Guardrail())

# Run attack
print("Running Go-Explore attack (5 seconds)...")
attacker = AttackAlgorithm({"max_turns": 3, "branch_batch": 8})
findings = attacker.run(env, {"seconds": 5})

print(f"\n{'=' * 70}")
print("RESULTS")
print(f"{'=' * 70}")
print(f"Total findings: {len(findings)}")

if findings:
    print(f"\nBreaches found:")
    for i, f in enumerate(findings[:5], 1):
        print(f"\n[{i}] {' -> '.join(f['user_messages'])}")
        for p in f.get("predicates", []):
            print(f"    ⚠️  {p['predicate']} (severity: {p['severity']})")
else:
    print("\n⚠️  No breaches found")
    print("   This could mean:")
    print("   - Guardrail is working well")
    print("   - Need more time/exploration")
    print("   - Agent not triggering vulnerabilities")

print(f"\n{'=' * 70}")
print("✓ Test complete")
print(f"{'=' * 70}\n")
