#!/usr/bin/env python3
"""
Run attack demo using OpenAI API instead of gpt-oss-20b.

This bypasses the GPT_OSS_MODEL_PATH requirement and uses OpenAI's API directly.
Set OPENAI_API_KEY environment variable to use.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from aicomp_sdk.agents import build_agent
from aicomp_sdk.attacks.baselines.guardrail_allow import Guardrail as BaselineGuardrail
from aicomp_sdk.core.env import SandboxEnv
from aicomp_sdk.core.predicates import eval_predicates

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))


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
    """Run attack demo with OpenAI."""
    print("=" * 70)
    print("LPCI ATTACK DEMO - Using OpenAI API")
    print("=" * 70)

    if _select_openai_demo_agent() == "deterministic":
        print("\n⚠️  WARNING: OPENAI_API_KEY not set")
        print("   Will use deterministic fallback agent")
        print("   Set OPENAI_API_KEY to use real OpenAI model\n")
    else:
        print("\n✓ Using OpenAI API (gpt-4o-mini)\n")

    sys.path.insert(0, str(Path(__file__).parent / "examples_hooks_submission"))
    from attack_simple import AttackAlgorithm

    fixtures = Path(__file__).parent / "fixtures"
    env = _build_demo_env(seed=42, fixtures_dir=fixtures)

    print("Running attack algorithm with LPCI hooks...\n")
    attacker = AttackAlgorithm()
    findings = attacker.run(env, {"budget_s": 30, "steps": 10})

    print(f"\n{'=' * 70}")
    print("RESULTS")
    print(f"{'=' * 70}\n")

    print(f"Total findings: {len(findings)}")

    validated = []
    for i, finding in enumerate(findings, 1):
        trace = finding.get("trace", {})
        predicates = eval_predicates(trace)

        if predicates:
            validated.append(finding)
            print(f"\n[Breach {i}] {finding.get('prompt', 'N/A')}")
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
            if event.get("output"):
                preview = event["output"][:100]
                if "ACTION:" in preview:
                    print("       → Contains ACTION directive!")

    print(f"\n{'=' * 70}")
    print("DEMO COMPLETE")
    print(f"{'=' * 70}")


if __name__ == "__main__":
    main()
