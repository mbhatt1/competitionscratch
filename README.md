# JED: Replay-Based Security Benchmark for Tool-Using AI Agents

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PyPI version](https://img.shields.io/pypi/v/aicomp-sdk.svg)](https://pypi.org/project/aicomp-sdk/)

JED is a Python SDK and benchmark for evaluating tool-using agents under adversarial pressure.

It supports three package workflows:
- attack-only evaluation
- guardrail-only evaluation
- combined attack+defense evaluation

Documentation: <https://mbhatt1.github.io/competitionscratch/>

## Choose Your Workflow

Use `aicomp evaluate` when you want the scorer-style public interface and stable machine-readable artifacts.
Use `aicomp test` when you are iterating locally and want run history, `compare`, and `visualize`.

| Workflow | Submission | Primary entrypoint | Default env | Output |
| --- | --- | --- | --- | --- |
| Kaggle red-team | `attack.py` | `aicomp evaluate redteam` | `sandbox` | normalized attack score |
| Package attack-only | `attack.py` | `aicomp test redteam` | `sandbox` | normalized attack score |
| Package guardrail-only | `guardrail.py` | `aicomp test defense` | `sandbox` | defense score |
| Package dual-track | `submission.zip` with `attack.py` and `guardrail.py` | `aicomp test dual` | `sandbox` | attack + defense |

The public Kaggle competition uses the attack-only path. The package itself supports all three workflows.

## Install

From PyPI:

```bash
pip install aicomp-sdk
```

From source:

```bash
git clone https://github.com/mbhatt1/competitionscratch.git
cd competitionscratch
pip install -e .
```

## Quick Start: Attack-Only

Generate a starter submission:

```bash
aicomp init attack
aicomp validate redteam attack.py
aicomp test redteam attack.py --budget-s 60 --agent deterministic
```

Run the standalone public-path scorer locally:

```bash
aicomp evaluate \
  redteam \
  attack.py \
  --budget-s 60 \
  --agent deterministic \
  --env gym
```

`attack.py` must define `AttackAlgorithm`, inherit from `AttackAlgorithmBase`, and return `list[AttackCandidate]`.

If you want CLI behavior that matches the public Kaggle default more closely, use `aicomp evaluate redteam attack.py --env gym`.

The standalone evaluator defaults to a short terminal summary. Use `--verbosity progress` for package-owned progress messages. Add `--save-transcript`, `--save-framework-events`, and `--save-agent-debug` when you want `transcript.log`, `framework.jsonl`, and `agent-debug.jsonl` written under `--artifacts-dir`.

`aicomp test` keeps its explicit-path diagnostics flags: `--transcript-file`, `--event-log-file`, and `--agent-debug-jsonl`.

## Other Supported Package Workflows

Guardrail-only:

```bash
aicomp init guardrail
aicomp validate defense guardrail.py
aicomp test defense guardrail.py --budget-s 60 --agent deterministic
```

Dual-track:

```bash
zip submission.zip attack.py guardrail.py
aicomp test dual submission.zip --budget-s 60 --agent deterministic
aicomp evaluate dual submission.zip --budget-s 60 --agent deterministic --env sandbox
```

## How Scoring Works

Attack scoring is replay-based. The evaluator replays each returned `AttackCandidate` and recomputes:
- the trace
- triggered predicates
- the cell signature
- the final score

The public Kaggle leaderboard uses normalized attack score only. Package guardrail-only and dual-track workflows also expose defense scoring.

## SDK Notes

- `SandboxEnv` is the default environment for local evaluator runs.
- `GymAttackEnv` is available when you explicitly pass `--env gym` for Kaggle-style parity.
- Direct `SandboxEnv(...)` construction requires an explicit `agent=` instance.
- `aicomp test` defaults to `1800` seconds for `redteam`, `1800` seconds for `defense`, and `3600` seconds total for `dual` (`1800`/`1800` split).

## Documentation

- [`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md)
- [`docs/KAGGLE_REDTEAM_GUIDE.md`](docs/KAGGLE_REDTEAM_GUIDE.md)
- [`docs/GUARDRAILS_GUIDE.md`](docs/GUARDRAILS_GUIDE.md)
- [`docs/SCORING.md`](docs/SCORING.md)
- [`docs/API_REFERENCE.md`](docs/API_REFERENCE.md)

## Repository Layout

- [`aicomp_sdk/`](aicomp_sdk/) - package code
- [`examples/`](examples/) - runnable examples
- [`tests/`](tests/) - unit and integration tests

## License

MIT. See [`LICENSE`](LICENSE).
