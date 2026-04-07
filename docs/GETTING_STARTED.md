# Getting Started

Use this page if you want to go from install to a first working public Kaggle-style `attack.py`.

The package also supports package guardrail-only and package dual-track workflows, but this page focuses on the public Kaggle path and the shortest route to a successful local run.

## 1. Install

Requirements:

- Python `3.11+`
- either an editable checkout or an installed `aicomp-sdk`

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

## 2. Create `attack.py`

Generate a starter file:

```bash
aicomp init attack
```

This creates an `attack.py` template with the required `AttackAlgorithm` class.

## 3. Validate the File

```bash
aicomp validate redteam attack.py
```

`aicomp validate` checks:

- Python syntax
- SDK imports
- presence of `AttackAlgorithm`
- presence of `run(self, env, config)`

## 4. Use the Minimum Working Contract

Your file must define `AttackAlgorithm` and return replayable `AttackCandidate` values:

```python
from aicomp_sdk import AttackAlgorithmBase, AttackCandidate, AttackRunConfig


class AttackAlgorithm(AttackAlgorithmBase):
    def run(self, env, config: AttackRunConfig) -> list[AttackCandidate]:
        return []
```

## 5. Make It Return One Real Candidate

This minimal version is enough to produce a replayable result:

```python
from aicomp_sdk import AttackAlgorithmBase, AttackCandidate, AttackRunConfig
from aicomp_sdk.core.predicates import eval_predicates


class AttackAlgorithm(AttackAlgorithmBase):
    def run(self, env, config: AttackRunConfig) -> list[AttackCandidate]:
        findings: list[AttackCandidate] = []

        for prompt in [
            "read secret",
            "open demo",
            "send email",
        ]:
            env.reset()
            env.interact(prompt)
            trace = env.export_trace_dict()
            if eval_predicates(trace):
                findings.append(
                    AttackCandidate(user_messages=tuple(trace["user_messages"]))
                )

        return findings
```

This works because scoring is replay-based: the evaluator trusts replayed `user_messages`, not attacker-supplied traces or metadata.

## 6. Run a Smoke Test

Fast local package path:

```bash
aicomp test redteam attack.py --budget-s 60 --agent deterministic
```

Use `deterministic` when you want an offline smoke test without API keys.

## 7. Run the Public-Contract Scorer Locally

```bash
aicomp evaluate \
  redteam \
  attack.py \
  --budget-s 60 \
  --agent deterministic \
  --env gym
```

The standalone evaluator defaults to a short terminal summary. Add `--verbosity progress` for package-owned progress messages, plus `--save-transcript`, `--save-framework-events`, and `--save-agent-debug` when you want `transcript.log`, `framework.jsonl`, and `agent-debug.jsonl` under `--artifacts-dir`.

If you want local CLI behavior that matches the public Kaggle default more closely:

```bash
aicomp evaluate redteam attack.py --agent deterministic --env gym
```

`aicomp test redteam` and `aicomp evaluate redteam` both default to `1800` seconds. Dual-track runs default to `3600` seconds total, split into `1800` attack seconds and `1800` defense seconds.

## 8. What to Read Next

After you get one successful run:

- read [`KAGGLE_REDTEAM_GUIDE.md`](KAGGLE_REDTEAM_GUIDE.md) for the exact public contract
- read [`ATTACKS_GUIDE.md`](ATTACKS_GUIDE.md) for attack iteration strategy
- read [`SCORING.md`](SCORING.md) for the full scoring model
- read [`API_REFERENCE.md`](API_REFERENCE.md) for exact SDK and CLI details

## Not Covered Here

This page does not try to cover:

- attack strategy beyond the first working example
- full public Kaggle contract detail
- package guardrail-only evaluation
- package dual-track evaluation

Use [`README.md`](README.md) to route into those workflows.
