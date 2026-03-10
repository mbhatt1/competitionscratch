# Archived Research Scripts

This directory contains older research scripts that predate the current public SDK shape.

They are still archived because they are not part of the supported product surface, but they
have been updated to run against the current codebase.

## Current Status

These scripts now target the current SDK using:

- `SandboxEnv` with explicit agent construction
- the current baseline Go-Explore attacker where applicable
- current fixture paths via `fixtures/`

The scripts intentionally keep their original Sandbox-based research setup. They do not switch
to the Gymnasium wrapper by default.

## Important Caveats

- These are research utilities, not stable public APIs.
- Most OpenAI-backed scripts require `OPENAI_API_KEY`.
- `compare_guardrails.py` uses the modern `examples.attacks.attack_working` attack contract and
  replays returned `AttackCandidate` chains back through `SandboxEnv` to preserve the original
  comparison semantics.
- `test_collaborative_multiagent.py` still simulates collaboration. It does not retrofit true
  shared-archive integration into the baseline attacker.

## Shared Helper

The archived scripts rely on `archived_imports.py` for:

- repository path setup
- fixture lookup
- explicit agent creation
- current `SandboxEnv` construction

If you need to adjust archived script wiring, change that helper first.

## Script Groups

Deterministic / local-only:

- `compare_guardrails.py`
- `test_seed_sensitivity.py`

OpenAI-backed:

- `compare_guardrails_openai.py`
- `run_comprehensive_experiments.py`
- `collect_all_experimental_data.py`
- `test_collaborative_multiagent.py`
- `test_ensemble_diversity_scaling.py`
- `test_ensemble_diversity_scaling_guardrail.py`
- `test_ensemble_vs_enhanced.py`
- `test_negative_rewards.py`

## Recommended Usage

Run these from the repository root so their output files land in predictable locations.

Examples:

```bash
./.venv/bin/python research/archived_scripts/compare_guardrails.py
./.venv/bin/python research/archived_scripts/test_seed_sensitivity.py
```

For the OpenAI-backed scripts:

```bash
export OPENAI_API_KEY=...
./.venv/bin/python research/archived_scripts/compare_guardrails_openai.py
```
