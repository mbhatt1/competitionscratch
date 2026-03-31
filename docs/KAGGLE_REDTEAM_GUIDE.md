# Kaggle Red-Team Guide

Use this page when you need the exact contract for the public Kaggle path.

This is the canonical contract guide for public Kaggle submissions. For first success and local development workflow, start with [`GETTING_STARTED.md`](GETTING_STARTED.md) and [`ATTACKS_GUIDE.md`](ATTACKS_GUIDE.md).

## Public Kaggle Contract

The public Kaggle path requires:

- submit `attack.py` only
- define a class named `AttackAlgorithm`
- inherit from `AttackAlgorithmBase`
- return `list[AttackCandidate]`
- use the public default attack budget of `1800` seconds unless overridden
- expect the default evaluation environment to be `gym`
- expect the public leaderboard score to be normalized attack score only

The package also supports package guardrail-only and package dual-track workflows, but those are not part of the public Kaggle submission contract.

## Filename and Class Requirements

For the public Kaggle path, use the required submission filename:

```bash
aicomp evaluate redteam attack.py
```

Current enforcement:

- the module must define `AttackAlgorithm`
- local `aicomp evaluate redteam` runs accept any `.py` filename
- the submitted public artifact should still be named `attack.py`

Package attack-only testing is more flexible and can evaluate any `.py` file that defines `AttackAlgorithm`, but the public Kaggle path expects `attack.py`.

## Minimal Public Submission

```python
from aicomp_sdk import AttackAlgorithmBase, AttackCandidate, AttackRunConfig


class AttackAlgorithm(AttackAlgorithmBase):
    def run(self, env, config: AttackRunConfig) -> list[AttackCandidate]:
        return []
```

The safest return shape is a list of replayable `AttackCandidate` message chains.

## Public Evaluator Defaults

`aicomp evaluate redteam` currently defaults to:

- `--budget-s 1800`
- `--env sandbox`
- normalized attack scoring

Pass `--env gym` when you want local behavior that matches the public Kaggle environment.

It also writes:

- `score.txt` with the normalized attack score
- `report.json` with the attack summary and evaluator metadata

Both files are written under the evaluator artifact directory, which defaults to `evaluation_artifacts/` and can be changed with `--artifacts-dir`.

Current output control:

- terminal output defaults to a short summary
- use `--verbosity progress` for package-owned progress messages
- use `--save-transcript` for `transcript.log`
- use `--save-framework-events` for `framework.jsonl`
- use `--save-agent-debug` for `agent-debug.jsonl`

## Environment Contract

The public Kaggle environment uses `GymAttackEnv`, but local CLI runs only use it when you pass `--env gym`.

Current Gym-style behavior:

```python
obs, info = env.reset()
obs, reward, terminated, truncated, info = env.step("message")
```

Current semantics:

- `reward` is always `0.0`
- `terminated` is always `False`
- `truncated` becomes `True` when `max_episode_messages` is reached
- `info` includes the trace, predicates, and cell signature

Compatibility helpers remain available:

- `env.interact(...)`
- `env.export_trace_dict()`
- `env.snapshot()`
- `env.restore(...)`

Hosted evaluator runs expose an opaque attack environment wrapper. Guardrail internals
are not part of the submission contract, and attacker-visible traces redact block
reasons to `denied` and `confirm_required`.

For custom guardrail selection in hosted evaluator runs, see
[`API_REFERENCE.md`](API_REFERENCE.md#custom-attack-guardrails).

## Replay and Scoring Rules

The public leaderboard uses normalized attack score only.

The evaluator does not trust attacker-supplied traces, predicate labels, novelty metadata, or score hints. It replays each `AttackCandidate` and recomputes:

- the trace
- predicate triggers
- cell signatures
- final score

That is why the public contract is best satisfied by returning clean, replayable user-message chains.

For the full scoring model, normalization constants, and replay limits, see [`SCORING.md`](SCORING.md).

## Local Parity Commands

Use these when you want local behavior that matches the public Kaggle path as closely as possible:

Fast smoke test:

```bash
aicomp test redteam attack.py --budget-s 60 --agent deterministic
```

Public-contract scorer:

```bash
aicomp evaluate \
  redteam \
  attack.py \
  --budget-s 60 \
  --agent deterministic \
  --env gym
```

Official-budget CLI equivalent:

```bash
aicomp test redteam attack.py --budget-s 1800 --agent deterministic --env gym
```

## What This Page Does Not Cover

This page does not cover:

- how to get to a first working `attack.py`
- attack search strategy or iteration loops
- package guardrail-only evaluation
- package dual-track evaluation

Use these pages for those topics:

- [`GETTING_STARTED.md`](GETTING_STARTED.md)
- [`ATTACKS_GUIDE.md`](ATTACKS_GUIDE.md)
- [`SCORING.md`](SCORING.md)
- [`API_REFERENCE.md`](API_REFERENCE.md)
