# JED: Replay-Based Security Benchmark for Tool-Using AI Agents

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PyPI version](https://img.shields.io/pypi/v/aicomp-sdk.svg)](https://pypi.org/project/aicomp-sdk/)

JED is a Python SDK and benchmark for evaluating tool-using agents under adversarial pressure.

It supports three package workflows:
- attack-only evaluation
- guardrail-only evaluation
- combined attack+defense evaluation

Documentation: <https://mbhatt1.github.io/competitionscratch/>

## Choose Your Workflow

| Workflow | Submission | Primary entrypoint | Default env | Output |
| --- | --- | --- | --- | --- |
| Kaggle red-team | `attack.py` | `evaluation_redteam.py` | `gym` | normalized attack score |
| Package attack-only | `attack.py` | `aicomp test --track redteam` | `gym` | normalized attack score |
| Package guardrail-only | `guardrail.py` | `aicomp test --track defense` | `sandbox` | defense score |
| Package dual-track | `submission.zip` with `attack.py` and `guardrail.py` | `evaluation.py` or `aicomp test --track dual` | `sandbox` | attack + defense |

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
aicomp validate attack.py
aicomp test attack.py --track redteam --quick --agent deterministic
```

Run the standalone Kaggle-style scorer locally:

```bash
python evaluation_redteam.py \
  --submission attack.py \
  --budget-s 60 \
  --agent deterministic \
  --env gym
```

`attack.py` must define `AttackAlgorithm`, inherit from `AttackAlgorithmBase`, and return `list[AttackCandidate]`.

If you want CLI behavior that matches the public Kaggle default, use `--track redteam --budget-s 1800`.

## Other Supported Package Workflows

Guardrail-only:

```bash
aicomp init guardrail
aicomp validate guardrail.py --type guardrail
aicomp test guardrail.py --track defense --quick --agent deterministic
```

Dual-track:

```bash
zip submission.zip attack.py guardrail.py
aicomp test submission.zip --track dual --quick --agent deterministic
python evaluation.py --submission_zip submission.zip --budget-s 60 --agent deterministic --env sandbox
```

## How Scoring Works

Attack scoring is replay-based. The evaluator replays each returned `AttackCandidate` and recomputes:
- the trace
- triggered predicates
- the cell signature
- the final score

The public Kaggle leaderboard uses normalized attack score only. Package guardrail-only and dual-track workflows also expose defense scoring.

## SDK Notes

- `GymAttackEnv` is the default environment for Kaggle-style red-team evaluation.
- `SandboxEnv` is the default environment for package guardrail-only and dual-track workflows.
- As of `2.0.0`, direct `SandboxEnv(...)` construction requires an explicit `agent=` instance.
- `aicomp test` defaults to `3600` seconds total because it supports all three package workflows.

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
- [`evaluation_redteam.py`](evaluation_redteam.py) - Kaggle-style red-team scorer
- [`evaluation.py`](evaluation.py) - package dual-track evaluator

## License

MIT. See [`LICENSE`](LICENSE).
