# Examples Quick Start

This guide is for the current example files under `examples/`.

It focuses on two use cases:

- attack-only Kaggle-style iteration
- local experimental attack+guardrail iteration

## 1. Attack-Only Example

Copy a simple example to the repository root:

```bash
cp examples/attacks/attack_gym_step.py attack.py
```

Run the example smoke test:

```bash
python examples/test_attack_submission.py
```

Run the standalone scorer:

```bash
python evaluation_redteam.py --submission attack.py --budget-s 60 --agent deterministic --env gym
```

## 2. Local Attack+Guardrail Example

Copy an attack and guardrail pair:

```bash
cp examples/attacks/attack_working.py attack.py
cp examples/guardrails/guardrail_optimal.py guardrail.py
```

Run the local smoke test:

```bash
python examples/test_submission.py
```

Package them for the local dual-track evaluator:

```bash
zip submission.zip attack.py guardrail.py
python evaluation.py --submission_zip submission.zip --budget-s 60 --agent deterministic --env sandbox
```

## Experimental Hook-Based Examples

The repository also includes experimental LPCI / hook-based examples:

- [`attacks/attack_simple.py`](attacks/attack_simple.py)
- [`attacks/attack_goexplore_lpci.py`](attacks/attack_goexplore_lpci.py)
- [`guardrails/guardrail_simple.py`](guardrails/guardrail_simple.py)

Those are useful for local experimentation, but the stable public contract is still:

- `AttackAlgorithm.run(...) -> list[AttackCandidate]`
- `Guardrail.decide(...) -> Decision`

## Recommended Order

1. start with `attack_gym_step.py` if you want the cleanest red-team example
2. switch to `attack_working.py` or `attack_goexplore_working.py` if you want a stronger local baseline
3. add `guardrail_optimal.py` or another guardrail example only if you are using the local defense/dual-track flow

## Related Docs

- [`../docs/GETTING_STARTED.md`](../docs/GETTING_STARTED.md)
- [`../docs/KAGGLE_REDTEAM_GUIDE.md`](../docs/KAGGLE_REDTEAM_GUIDE.md)
- [`../docs/GUARDRAILS_GUIDE.md`](../docs/GUARDRAILS_GUIDE.md)
