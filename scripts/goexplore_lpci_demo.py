#!/usr/bin/env python3
"""Run the experimental Go-Explore + LPCI example attack locally."""

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
from aicomp_sdk.attacks.baselines.guardrail_allow import Guardrail
from aicomp_sdk.core.env import SandboxEnv
from examples.attacks.attack_goexplore_lpci import AttackAlgorithm


def _build_demo_env(*, seed: int, fixtures_dir: Path) -> SandboxEnv:
    if os.environ.get("GPT_OSS_MODEL_PATH"):
        selection = "auto"
    elif os.environ.get("OPENAI_API_KEY"):
        selection = "openai"
    else:
        selection = "deterministic"
    return SandboxEnv(
        seed=seed,
        fixtures_dir=fixtures_dir,
        agent=build_agent(selection),
        guardrail=Guardrail(),
    )


def main() -> None:
    fixtures = repo_root / "fixtures"

    try:
        env = _build_demo_env(seed=123, fixtures_dir=fixtures)
    except RuntimeError as err:
        if "OpenAI SDK is not available" not in str(err):
            raise
        print("OpenAI SDK unavailable; falling back to deterministic demo agent")
        env = SandboxEnv(
            seed=123,
            fixtures_dir=fixtures,
            agent=build_agent("deterministic"),
            guardrail=Guardrail(),
        )

    print("\nRunning Go-Explore + LPCI hybrid attack...")
    print("=" * 70)

    attacker = AttackAlgorithm({"max_turns": 4, "branch_batch": 8})
    findings = attacker.run(env, AttackRunConfig(time_budget_s=10))

    print(f"\n{'=' * 70}")
    print("Go-Explore + LPCI Results")
    print(f"{'=' * 70}")
    print(f"Total findings: {len(findings)}")

    if findings:
        print("\nBreaches discovered:")
        for index, candidate in enumerate(findings[:5], 1):
            print(f"\n[{index}] {' -> '.join(candidate.user_messages)}")
    else:
        print("\nNo breaches found in this run")
        print("Try increasing the time budget or inspecting the installed hooks.")

    print(f"\n{'=' * 70}")
    print("The attack combined:")
    print("  1. Go-Explore's systematic exploration")
    print("  2. LPCI hooks for payload injection")
    print("  3. Tool poisoning to target sensitive resources")
    print(f"{'=' * 70}\n")


if __name__ == "__main__":
    main()
