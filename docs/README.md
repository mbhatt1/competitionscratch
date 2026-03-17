# JED Documentation

This documentation set covers the JED package as it exists today: a Python SDK and benchmark for evaluating tool-using agents under adversarial pressure.

JED supports three package workflows:
- attack-only evaluation
- guardrail-only evaluation
- dual-track attack+defense evaluation

The public Kaggle competition uses the attack-only path. The package itself supports all three.

## Choose Your Path

### I am building a public Kaggle submission

Start here:
- [`GETTING_STARTED.md`](GETTING_STARTED.md) for the fastest path to a working `attack.py`
- [`KAGGLE_REDTEAM_GUIDE.md`](KAGGLE_REDTEAM_GUIDE.md) for the public submission contract
- [`SCORING.md`](SCORING.md) for the normalized attack scoring model
- [`COMPETITION_RULES.md`](COMPETITION_RULES.md) as a placeholder until the official Kaggle rules page is live

Use this path if:
- you are submitting `attack.py`
- you want behavior that matches `evaluation_redteam.py`
- you care about the public leaderboard contract

### I am developing attacks with the package

Start here:
- [`ATTACKS_GUIDE.md`](ATTACKS_GUIDE.md) for attack strategy, replay behavior, and environment usage
- [`API_REFERENCE.md`](API_REFERENCE.md) for SDK and CLI details
- [`../examples/attacks/attack_gym_step.py`](../examples/attacks/attack_gym_step.py) for a minimal runnable example

Use this path if:
- you are iterating on `AttackAlgorithm`
- you want to use `aicomp test --track redteam`
- you need package-level attack experimentation outside the public Kaggle flow

### I am developing guardrails

Start here:
- [`GUARDRAILS_GUIDE.md`](GUARDRAILS_GUIDE.md) for the `Guardrail.decide(...)` contract
- [`SCORING.md`](SCORING.md) for defense scoring
- [`TESTING_GUIDE.md`](TESTING_GUIDE.md) for validation and CI-aligned test commands
- [`API_REFERENCE.md`](API_REFERENCE.md) for guardrail and environment details

Use this path if:
- you are writing `guardrail.py`
- you want to test defense-only behavior with `aicomp test --track defense`
- you want to understand the current context keys and decision types

### I am evaluating attacks and defenses together

Start here:
- [`COMPETITION_DESIGN.md`](COMPETITION_DESIGN.md) for the package workflow split
- [`GUARDRAILS_GUIDE.md`](GUARDRAILS_GUIDE.md) for the defense side
- [`ATTACKS_GUIDE.md`](ATTACKS_GUIDE.md) for the offense side
- [`../examples/README.md`](../examples/README.md) for runnable examples and smoke tests

Use this path if:
- you are packaging `submission.zip`
- you want to measure attack and defense together
- you need the package dual-track workflow rather than the public Kaggle contract

## Core Concepts

These ideas appear throughout the docs:

- Replay-based scoring: evaluators replay returned attack candidates and recompute traces, predicates, and cell signatures before scoring.
- Workflow split: `evaluation_redteam.py` is the public attack-only scorer; `aicomp test` supports attack-only, guardrail-only, and dual-track package workflows; `evaluation.py` is the standalone dual-track evaluator.
- Environment defaults: red-team evaluation defaults to `gym`; guardrail-only and dual-track package evaluation default to `sandbox`.
- Submission shapes: public Kaggle uses `attack.py`; package workflows also support `guardrail.py` and `submission.zip`.

## Recommended Reading Order

If you are new to the project:
1. [`GETTING_STARTED.md`](GETTING_STARTED.md)
2. [`KAGGLE_REDTEAM_GUIDE.md`](KAGGLE_REDTEAM_GUIDE.md)
3. [`SCORING.md`](SCORING.md)
4. one of [`ATTACKS_GUIDE.md`](ATTACKS_GUIDE.md) or [`GUARDRAILS_GUIDE.md`](GUARDRAILS_GUIDE.md), depending on your workflow
5. [`API_REFERENCE.md`](API_REFERENCE.md) when you need exact interfaces and defaults

## Examples and Validation

Examples:
- [`../examples/README.md`](../examples/README.md)
- [`../examples/attacks/attack_gym_step.py`](../examples/attacks/attack_gym_step.py)
- [`../examples/guardrails/guardrail_optimal.py`](../examples/guardrails/guardrail_optimal.py)

Useful validation paths:
- `aicomp test attack.py --track redteam --quick`
- `aicomp test guardrail.py --track defense --quick`
- `aicomp test submission.zip --track dual --quick`

## Quick Reference

- Public Kaggle submission shape: `attack.py`
- Public Kaggle entrypoint: [`../evaluation_redteam.py`](../evaluation_redteam.py)
- Package dual-track entrypoints: [`../evaluation.py`](../evaluation.py) and `aicomp test --track dual`
- Default public attack budget: `1800` seconds
- Default `aicomp test` budget: `3600` seconds total
