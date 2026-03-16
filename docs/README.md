# JED Documentation

This directory is the documentation hub for the current JED SDK.

## Start Here

- [`GETTING_STARTED.md`](GETTING_STARTED.md) - fastest path from install to a working `attack.py`
- [`KAGGLE_REDTEAM_GUIDE.md`](KAGGLE_REDTEAM_GUIDE.md) - official red-team contract
- [`COMPETITION_RULES.md`](COMPETITION_RULES.md) - submission and evaluator rules
- [`SCORING.md`](SCORING.md) - replay-based scoring model

## Core SDK Guides

- [`ATTACKS_GUIDE.md`](ATTACKS_GUIDE.md) - how to build attack algorithms
- [`API_REFERENCE.md`](API_REFERENCE.md) - public SDK and CLI surface
- [`FAQ.md`](FAQ.md) - short answers to common questions

## Local-Only Workflow Docs

These pages describe supported repository workflows that are not part of the public Kaggle submission contract:

- [`GUARDRAILS_GUIDE.md`](GUARDRAILS_GUIDE.md)
- [`COMPETITION_DESIGN.md`](COMPETITION_DESIGN.md)
- [`TESTING_GUIDE.md`](TESTING_GUIDE.md)

## Examples

- [`../examples/README.md`](../examples/README.md)
- [`../examples/test_attack_submission.py`](../examples/test_attack_submission.py)
- [`../examples/attacks/attack_gym_step.py`](../examples/attacks/attack_gym_step.py)

## Contract Reminders

- Official Kaggle submission shape: `attack.py` only
- Official Kaggle entrypoint: [`../evaluation_redteam.py`](../evaluation_redteam.py)
- Official Kaggle default attack budget: `1800` seconds
- `aicomp test` defaults to `3600` seconds total unless you pass `--budget-s`
- Red-team evaluation defaults to `gym`; local dual-track and defense default to `sandbox`
