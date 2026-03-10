# Examples

This directory contains reference attacks, additional local guardrails, and small test scripts.

> Official Kaggle path: submit `attack.py` only. Guardrail examples remain in the repo for local experimentation and research.

## Recommended Starting Points

- [`../docs/KAGGLE_REDTEAM_GUIDE.md`](../docs/KAGGLE_REDTEAM_GUIDE.md)
- [`../docs/GETTING_STARTED.md`](../docs/GETTING_STARTED.md)
- [`test_attack_submission.py`](test_attack_submission.py)
- [`attacks/attack_gym_step.py`](attacks/attack_gym_step.py)

## Attack Examples

- [`attacks/attack.py`](attacks/attack.py): fuller reference attack
- [`attacks/attack_simple.py`](attacks/attack_simple.py): simple starting point
- [`attacks/attack_working.py`](attacks/attack_working.py): working attack patterns
- [`attacks/attack_goexplore_working.py`](attacks/attack_goexplore_working.py): Go-Explore style example
- [`attacks/attack_goexplore_lpci.py`](attacks/attack_goexplore_lpci.py): advanced LPCI-flavored example
- [`attacks/attack_gym_step.py`](attacks/attack_gym_step.py): Gym-style message-step example

## Guardrail Examples

These are supported local-only examples:

- [`guardrails/guardrail.py`](guardrails/guardrail.py)
- [`guardrails/guardrail_simple.py`](guardrails/guardrail_simple.py)
- [`guardrails/guardrail_optimal.py`](guardrails/guardrail_optimal.py)
- [`guardrails/guardrail_taint_tracking.py`](guardrails/guardrail_taint_tracking.py)
- [`guardrails/guardrail_dataflow.py`](guardrails/guardrail_dataflow.py)
- [`guardrails/guardrail_prompt_injection.py`](guardrails/guardrail_prompt_injection.py)
- [`guardrails/guardrail_promptguard.py`](guardrails/guardrail_promptguard.py)
- [`guardrails/guardrail_perfect.py`](guardrails/guardrail_perfect.py)

## Test Scripts

- [`test_attack_submission.py`](test_attack_submission.py): Kaggle-style attack-only smoke test
- [`test_submission.py`](test_submission.py): zip-based attack+defense smoke test
- [`QUICK_START.md`](QUICK_START.md): advanced LPCI local attack+defense example flow

## Suggested Workflow

1. Copy an attack example to `attack.py`
2. Run the local attack smoke test
3. Inspect traces and improve prompt/search strategy
4. Rerun with longer budgets
5. Submit `attack.py`

Example:

```bash
cp examples/attacks/attack_simple.py attack.py
python examples/test_attack_submission.py
python evaluation_redteam.py --submission attack.py --budget-s 60 --agent deterministic --env gym
```
