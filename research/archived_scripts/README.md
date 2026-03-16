# Archived Research Scripts

This directory contains research scripts that predate the current public SDK documentation.

They are kept for reference and occasional reproduction work, but they are not part of the stable public API surface.

## Current Status

These scripts have been kept compatible with the current repository shape where practical:

- they construct `SandboxEnv` explicitly
- they use current fixture locations under `fixtures/`
- they rely on `archived_imports.py` for repo bootstrapping

They intentionally remain Sandbox-based research utilities. They do not attempt to mirror the public Kaggle red-team contract exactly.

## What To Expect

- script behavior is less stable than the main package APIs
- several scripts require `OPENAI_API_KEY`
- outputs are research artifacts, not canonical benchmark numbers

## Shared Helper

[`archived_imports.py`](archived_imports.py) owns the common wiring for:

- repository path setup
- fixture lookup
- environment construction
- agent construction

If one archived script breaks because of repo shape changes, check that helper first.

## Current Script Groups

Deterministic / local-focused:

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

Run archived scripts from the repository root:

```bash
./.venv/bin/python research/archived_scripts/compare_guardrails.py
./.venv/bin/python research/archived_scripts/test_seed_sensitivity.py
```

OpenAI-backed example:

```bash
export OPENAI_API_KEY=...
./.venv/bin/python research/archived_scripts/compare_guardrails_openai.py
```

If you need supported workflows, prefer the main docs and entrypoints instead:

- `evaluation_redteam.py`
- `evaluation.py`
- `aicomp test`
