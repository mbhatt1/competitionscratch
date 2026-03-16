#!/usr/bin/env python3
"""
Run Go-Explore attack demo using OpenAI API instead of gpt-oss-20b.

This bypasses the GPT_OSS_MODEL_PATH requirement and uses OpenAI's API directly.
Set OPENAI_API_KEY environment variable to use.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

repo_root = Path(__file__).resolve().parent.parent
repo_root_str = str(repo_root)
if repo_root_str not in sys.path:
    sys.path.insert(0, repo_root_str)

from aicomp_sdk.agents import build_agent
from aicomp_sdk.attacks import AttackRunConfig
from aicomp_sdk.attacks.baselines.attacker_goexplore import AttackAlgorithm
from aicomp_sdk.attacks.baselines.guardrail_allow import Guardrail as BaselineGuardrail
from aicomp_sdk.core.env import SandboxEnv
from aicomp_sdk.core.predicates import eval_predicates


def _select_openai_demo_agent() -> str:
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    return "deterministic"


def _build_demo_env(*, seed: int, fixtures_dir: Path) -> SandboxEnv:
    return SandboxEnv(
        seed=seed,
        fixtures_dir=fixtures_dir,
        agent=build_agent(_select_openai_demo_agent()),
        guardrail=BaselineGuardrail(),
    )


def main() -> None:
    """Run Go-Explore demo with OpenAI."""
    print("=" * 70)
    print("GO-EXPLORE ATTACK DEMO - Using OpenAI API")
    print("=" * 70)

    if _select_openai_demo_agent() == "deterministic":
        print("\n⚠️  OPENAI_API_KEY not set")
        print("   Will use deterministic fallback\n")
    else:
        print("\n✓ OPENAI_API_KEY found\n")

    fixtures = repo_root / "fixtures"
    env = _build_demo_env(seed=42, fixtures_dir=fixtures)

    print("Running improved Go-Explore with OpenAI agent...\n")
    attacker = AttackAlgorithm({"max_turns": 6, "branch_batch": 8})
    findings = attacker.run(env, AttackRunConfig(time_budget_s=30, max_steps=100))
    detailed_findings = attacker.last_run_details

    print(f"\n{'=' * 70}")
    print("RESULTS")
    print(f"{'=' * 70}\n")

    print(f"Total findings: {len(findings)}")

    validated = []
    for i, finding in enumerate(detailed_findings, 1):
        trace = finding.get("trace", {})
        predicates = eval_predicates(trace)

        if predicates:
            validated.append(finding)
            prompt = " -> ".join(trace.get("user_messages", []))
            print(f"\n[Breach {i}] {prompt}")
            for predicate in predicates:
                print(
                    f"  ⚠️  {predicate.get('predicate')} "
                    f"(severity: {predicate.get('severity')})"
                )
                print(f"     Evidence: {predicate.get('evidence', {})}")

    print(f"\n{'─' * 70}")
    print(f"Validated breaches: {len(validated)}/{len(findings)}")
    print(f"{'─' * 70}")

    if validated:
        print("\nExample breach trace:")
        trace = validated[0].get("trace", {})
        print(f"  User message: {trace.get('user_messages', [''])[0]}")
        print("  Tool events:")
        for event in trace.get("tool_events", [])[:5]:
            status = "✓" if event.get("ok") else "✗"
            print(f"    {status} {event.get('name')}({event.get('args', {})})")

    print(f"\n{'=' * 70}")
    print("DEMO COMPLETE")
    print(f"{'=' * 70}\n")


if __name__ == "__main__":
    main()
