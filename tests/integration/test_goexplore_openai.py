#!/usr/bin/env python3
"""
Test Go-Explore attack with OpenAI API
"""

import os
from pathlib import Path

from aicomp_sdk.agents import build_agent

# Import the baseline Go-Explore attacker
from aicomp_sdk.attacks.baselines.attacker_goexplore import AttackAlgorithm
from aicomp_sdk.attacks.baselines.guardrail_allow import Guardrail
from aicomp_sdk.core.env import SandboxEnv


def main() -> None:
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
    selection = "openai" if os.environ.get("OPENAI_API_KEY") else "deterministic"
    env = SandboxEnv(
        seed=42,
        fixtures_dir=fixtures,
        agent=build_agent(selection),
        guardrail=Guardrail(),
    )

    # Run attack
    print("Running Go-Explore attack (5 seconds)...")
    attacker = AttackAlgorithm({"max_turns": 3, "branch_batch": 8})
    findings = attacker.run(env, {"time_budget_s": 5})

    print(f"\n{'=' * 70}")
    print("RESULTS")
    print(f"{'=' * 70}")
    print(f"Total findings: {len(findings)}")

    if findings:
        print("\nBreaches found:")
        for i, finding in enumerate(findings[:5], 1):
            print(f"\n[{i}] {' -> '.join(finding['user_messages'])}")
            for predicate in finding.get("predicates", []):
                print(f"    ⚠️  {predicate['predicate']} (severity: {predicate['severity']})")
    else:
        print("\n⚠️  No breaches found")
        print("   This could mean:")
        print("   - Guardrail is working well")
        print("   - Need more time/exploration")
        print("   - Agent not triggering vulnerabilities")

    print(f"\n{'=' * 70}")
    print("✓ Test complete")
    print(f"{'=' * 70}\n")


if __name__ == "__main__":
    main()
