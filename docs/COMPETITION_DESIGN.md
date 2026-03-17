# Competition Design

Use this page when you want to understand why the repository has both the public Kaggle path and broader package workflows.

This is a repository design note, not a usage guide. For hands-on workflow instructions, use [`GETTING_STARTED.md`](GETTING_STARTED.md), [`KAGGLE_REDTEAM_GUIDE.md`](KAGGLE_REDTEAM_GUIDE.md), [`ATTACKS_GUIDE.md`](ATTACKS_GUIDE.md), or [`GUARDRAILS_GUIDE.md`](GUARDRAILS_GUIDE.md).

## Workflow Surfaces

The repository intentionally exposes two layers of use.

### Public Kaggle path

- submission shape: `attack.py`
- primary entrypoint: [`../evaluation_redteam.py`](../evaluation_redteam.py)
- default budget: `1800` seconds
- default environment: `gym`
- public score: normalized attack score only

### Package workflows

- submission shapes: `attack.py`, `guardrail.py`, or `submission.zip`
- primary entrypoints: `aicomp test` for attack-only, guardrail-only, and dual-track evaluation; [`../evaluation.py`](../evaluation.py) for standalone package dual-track evaluation
- default environment: `gym` for package attack-only evaluation, `sandbox` for package guardrail-only and package dual-track evaluation
- package scores: normalized attack score, defense score, or combined attack + defense

## Why Both Exist

The public Kaggle path stays intentionally narrow:

- one submission shape
- one scoring surface
- one public leaderboard number

The package workflows exist because the repository also needs to support local experimentation that the public competition does not expose directly:

- package attack-only iteration
- package guardrail-only development
- package dual-track attack+defense evaluation
- backend comparison and richer local inspection

## Why Dual-Track Evaluation Is Separate

Package dual-track evaluation measures two different things:

### Offense

- your attack
- current packaged optimal guardrail baseline
- normalized attack scoring

### Defense

- baseline attacker
- your guardrail
- defense scoring based on breaches and false positives

This split lets the package evaluate both sides of the system without changing the public Kaggle path.

## Budget Semantics

Current evaluator behavior follows the workflow surface:

- public Kaggle path: full budget goes to attack
- package guardrail-only: full budget goes to defense
- package dual-track: total budget is split evenly between offense and defense

That is why `evaluation.py --budget-s 3600` yields `1800` seconds for attack and `1800` seconds for defense.

The same split is reflected in `aicomp test --track dual`.

## Environment Choices

The current defaults are deliberate:

- `gym` for the public Kaggle path and package attack-only evaluation because it matches the Kaggle-style surface
- `sandbox` for package guardrail-only and package dual-track evaluation because direct SDK guardrail work usually wants the underlying environment

Both surfaces preserve the same common attack helpers:

- `reset()`
- `interact(...)`
- `export_trace_dict()`
- `snapshot()`
- `restore(...)`

## Scoring Design

The repository keeps the scoring surfaces separate on purpose:

- replay-based attack scoring so attacker metadata is not trusted
- normalized attack scoring for the public Kaggle path
- explicit defense scoring for package guardrail iteration
- combined attack + defense scoring only for package dual-track evaluation

For the exact scoring formulas and current constants, use [`SCORING.md`](SCORING.md).

## How To Use This Design Note

Use this page to understand the reasoning behind the workflow split.

Use these pages when you need to do actual work:

- public Kaggle path: [`GETTING_STARTED.md`](GETTING_STARTED.md), [`KAGGLE_REDTEAM_GUIDE.md`](KAGGLE_REDTEAM_GUIDE.md)
- package attack-only: [`ATTACKS_GUIDE.md`](ATTACKS_GUIDE.md), [`API_REFERENCE.md`](API_REFERENCE.md)
- package guardrail-only: [`GUARDRAILS_GUIDE.md`](GUARDRAILS_GUIDE.md), [`TESTING_GUIDE.md`](TESTING_GUIDE.md)
- package dual-track: [`examples/README.md`](../examples/README.md), [`API_REFERENCE.md`](API_REFERENCE.md)
