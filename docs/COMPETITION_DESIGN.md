# Competition Design

> Repository design note: this page explains why the repository contains both an official red-team scorer and a broader local dual-track workflow.

## Current Design Split

The repository intentionally supports two layers of use:

### 1. Public Kaggle red-team workflow

- submission: `attack.py`
- entrypoint: [`../evaluation_redteam.py`](../evaluation_redteam.py)
- default budget: `1800` seconds
- default environment: `gym`
- public score: normalized attack score only

### 2. Local SDK workflow

- submission: `guardrail.py` or `submission.zip`
- entrypoints: [`../evaluation.py`](../evaluation.py) and `aicomp test`
- default environment: `sandbox` for defense and dual-track flows
- local scores: defense score or attack + defense

## Why Both Exist

The red-team-only workflow is the public contract. The broader local workflow is still valuable because it lets you:

- prototype guardrails
- test attacks and defenses together
- compare agent backends locally
- inspect richer traces and local outputs before packaging a public submission

## Offense and Defense Evaluation

Current local dual-track evaluation still does two separate measurements:

### Offense

- your attack
- current packaged optimal guardrail baseline
- normalized attack scoring

### Defense

- baseline Go-Explore attacker
- your guardrail
- defense scoring based on breaches and false positives

## Budget Semantics

Current evaluator behavior:

- red-team-only: full budget goes to attack
- defense-only: full budget goes to defense
- dual-track: budget is split evenly between offense and defense

That split is why `evaluation.py --budget-s 3600` yields `1800` seconds for attack and `1800` seconds for defense.

## Environment Choices

Current defaults are deliberate:

- `gym` for red-team scoring because it matches the Kaggle-style surface
- `sandbox` for defense and dual-track flows because direct SDK guardrail work usually wants the underlying environment

Both surfaces preserve the common attack helpers:

- `reset()`
- `interact(...)`
- `export_trace_dict()`
- `snapshot()`
- `restore(...)`

## Scoring Philosophy

The current repository design keeps:

- replay-based attack scoring so attacker metadata is not trusted
- normalized attack scores for public red-team comparison
- explicit defense scoring for local guardrail iteration

The design goal is to keep the public competition simple while preserving a richer local research surface.

## Recommended Usage

Use the public path when you are working on a Kaggle submission:

```bash
aicomp test attack.py --track redteam --budget-s 1800 --agent deterministic
python evaluation_redteam.py --submission attack.py --budget-s 1800 --agent deterministic --env gym
```

Use the local path when you are iterating on guardrails or dual-track packages:

```bash
aicomp test guardrail.py --track defense --quick
aicomp test submission.zip --track dual --quick
python evaluation.py --submission_zip submission.zip --budget-s 60 --agent deterministic --env sandbox
```
