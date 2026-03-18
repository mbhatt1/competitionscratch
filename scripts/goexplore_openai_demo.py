#!/usr/bin/env python3
"""
Run the Go-Explore attack demo with an OpenAI-backed or deterministic agent.
"""

import os
from pathlib import Path

from aicomp_sdk.agents import build_agent
from aicomp_sdk.attacks import AttackRunConfig

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

    fixtures = Path(__file__).resolve().parent.parent / "fixtures"
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
    findings = attacker.run(env, AttackRunConfig(time_budget_s=5))
    detailed_findings = attacker.last_run_details

    print(f"\n{'=' * 70}")
    print("RESULTS")
    print(f"{'=' * 70}")
    print(f"Total findings: {len(findings)}")

    if findings:
        print("\nBreaches found:")
        for i, finding in enumerate(detailed_findings[:5], 1):
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
