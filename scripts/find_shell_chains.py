#!/usr/bin/env python3
"""
Find all action chains that successfully execute shell.run
Useful for identifying bypass patterns and allowed vs blocked chains
"""

import os
import sys
from pathlib import Path

from examples_hooks_submission.guardrail_prompt_injection import (
    Guardrail as PromptInjectionGuardrail,
)

from aicomp_sdk.agents import build_agent
from aicomp_sdk.attacks import AttackRunConfig
from aicomp_sdk.attacks.baselines.attacker_goexplore import AttackAlgorithm
from aicomp_sdk.attacks.baselines.guardrail_allow import Guardrail as AllowGuardrail
from aicomp_sdk.core.env import SandboxEnv

# Add repository root to path
repo_root = Path(__file__).parent.parent
sys.path.insert(0, str(repo_root))


# Check for OpenAI API key
if not os.environ.get("OPENAI_API_KEY"):
    print("WARNING: OPENAI_API_KEY not set. Using deterministic fallback.")

fixtures = repo_root / "fixtures"

print("=" * 70)
print("FINDING ALL SHELL.RUN EXECUTION CHAINS")
print("=" * 70)
print()

# Run Go-Explore with TARGETED shell exploration
print("\n[Step 1] Running Go-Explore with SHELL-TARGETED exploration...")
print("Using shell-focused prompt bank to maximize shell.run discovery")
env = SandboxEnv(
    seed=42,
    fixtures_dir=fixtures,
    agent=build_agent("auto"),
    guardrail=AllowGuardrail(),
)
attacker = AttackAlgorithm({"max_turns": 6, "branch_batch": 12, "target_shell": True})
findings = attacker.run(env, AttackRunConfig(time_budget_s=120))  # More time for targeted search
detailed_findings = attacker.last_run_details

# Extract all chains that executed shell.run
shell_chains_success = []
shell_chains_blocked = []

for f in detailed_findings:
    user_messages = f.get("user_messages", [])
    tool_events = f.get("trace", {}).get("tool_events", [])

    # Check if any tool event is shell.run
    for evt in tool_events:
        if evt.get("name") == "shell.run":
            chain_info = {
                "chain": " -> ".join(user_messages),
                "cmd": evt.get("args", {}).get("cmd", ""),
                "success": evt.get("ok", False),
                "error": evt.get("error", ""),
                "tool_sequence": [e.get("name") for e in tool_events],
                "depth": len(user_messages),
            }

            if evt.get("ok"):
                shell_chains_success.append(chain_info)
            else:
                shell_chains_blocked.append(chain_info)
            break  # Only count first shell.run in chain

print(f"\nDiscovered {len(shell_chains_success)} SUCCESSFUL shell.run chains")
print(f"Discovered {len(shell_chains_blocked)} BLOCKED shell.run chains")

# Test with guardrail using same targeted approach
print("\n[Step 2] Testing SHELL-TARGETED chains against Prompt Injection Guardrail...")
shell_chains_with_guard_success = []
shell_chains_with_guard_blocked = []

env_guard = SandboxEnv(
    seed=42,
    fixtures_dir=fixtures,
    agent=build_agent("auto"),
    guardrail=PromptInjectionGuardrail(),
)
attacker_guard = AttackAlgorithm({"max_turns": 6, "branch_batch": 12, "target_shell": True})
findings_guard = attacker_guard.run(env_guard, AttackRunConfig(time_budget_s=120))
detailed_findings_guard = attacker_guard.last_run_details

for f in detailed_findings_guard:
    user_messages = f.get("user_messages", [])
    tool_events = f.get("trace", {}).get("tool_events", [])

    for evt in tool_events:
        if evt.get("name") == "shell.run":
            chain_info = {
                "chain": " -> ".join(user_messages),
                "cmd": evt.get("args", {}).get("cmd", ""),
                "success": evt.get("ok", False),
                "error": evt.get("error", ""),
                "tool_sequence": [e.get("name") for e in tool_events],
                "depth": len(user_messages),
            }

            if evt.get("ok"):
                shell_chains_with_guard_success.append(chain_info)
            else:
                shell_chains_with_guard_blocked.append(chain_info)
            break

print(f"With Guardrail: {len(shell_chains_with_guard_success)} SUCCESSFUL shell.run chains")
print(f"With Guardrail: {len(shell_chains_with_guard_blocked)} BLOCKED shell.run chains")

# Display results
print(f"\n{'=' * 70}")
print("SUCCESSFUL SHELL.RUN CHAINS (NO GUARDRAIL)")
print(f"{'=' * 70}")

for i, chain in enumerate(shell_chains_success, 1):
    print(f"\n[{i}] Depth {chain['depth']}")
    print(f"    Chain: {chain['chain']}")
    print(f"    Command: {chain['cmd']}")
    print(f"    Tool sequence: {' -> '.join(chain['tool_sequence'])}")

if shell_chains_blocked:
    print(f"\n{'=' * 70}")
    print("BLOCKED SHELL.RUN CHAINS (NO GUARDRAIL)")
    print(f"{'=' * 70}")

    for i, chain in enumerate(shell_chains_blocked, 1):
        print(f"\n[{i}] Depth {chain['depth']}")
        print(f"    Chain: {chain['chain']}")
        print(f"    Reason: {chain['error']}")

print(f"\n{'=' * 70}")
print("SUCCESSFUL SHELL.RUN CHAINS (WITH GUARDRAIL)")
print(f"{'=' * 70}")

if shell_chains_with_guard_success:
    for i, chain in enumerate(shell_chains_with_guard_success, 1):
        print(f"\n[{i}] Depth {chain['depth']}")
        print(f"    Chain: {chain['chain']}")
        print(f"    Command: {chain['cmd']}")
        print(f"    Tool sequence: {' -> '.join(chain['tool_sequence'])}")
else:
    print("\n✓ No shell.run chains bypassed the guardrail!")

if shell_chains_with_guard_blocked:
    print(f"\n{'=' * 70}")
    print("BLOCKED SHELL.RUN CHAINS (WITH GUARDRAIL)")
    print(f"{'=' * 70}")

    for i, chain in enumerate(shell_chains_with_guard_blocked[:5], 1):  # Show first 5
        print(f"\n[{i}] Depth {chain['depth']}")
        print(f"    Chain: {chain['chain']}")
        print(f"    Reason: {chain['error']}")

# Summary
print(f"\n{'=' * 70}")
print("SUMMARY")
print(f"{'=' * 70}")
print(f"No Guardrail:")
print(f"  Successful shell.run: {len(shell_chains_success)}")
print(f"  Blocked shell.run: {len(shell_chains_blocked)}")

print(f"\nWith Guardrail:")
print(f"  Successful shell.run: {len(shell_chains_with_guard_success)}")
print(f"  Blocked shell.run: {len(shell_chains_with_guard_blocked)}")

blocked_count = len(shell_chains_success) - len(shell_chains_with_guard_success)
if len(shell_chains_success) > 0:
    block_rate = (blocked_count / len(shell_chains_success)) * 100
    print(
        f"\nGuardrail blocked {blocked_count}/{len(shell_chains_success)} chains ({block_rate:.1f}%)"
    )

print(f"\n{'=' * 70}\n")
