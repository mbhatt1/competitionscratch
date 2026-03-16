# Examples

This directory contains runnable attack examples, local-only guardrail examples, and smoke-test scripts.

> Official Kaggle path: submit `attack.py` only. Guardrail examples remain for local experimentation and repository workflows.

## Recommended Starting Points

- [`../docs/GETTING_STARTED.md`](../docs/GETTING_STARTED.md)
- [`../docs/KAGGLE_REDTEAM_GUIDE.md`](../docs/KAGGLE_REDTEAM_GUIDE.md)
- [`test_attack_submission.py`](test_attack_submission.py)
- [`attacks/attack_gym_step.py`](attacks/attack_gym_step.py)

## Attack Examples

- [`attacks/attack.py`](attacks/attack.py) - fuller example attack
- [`attacks/attack_simple.py`](attacks/attack_simple.py) - experimental hook-based attack
- [`attacks/attack_working.py`](attacks/attack_working.py) - practical local attack example
- [`attacks/attack_goexplore_working.py`](attacks/attack_goexplore_working.py) - Go-Explore-style attacker
- [`attacks/attack_goexplore_lpci.py`](attacks/attack_goexplore_lpci.py) - LPCI-flavored attack variant
- [`attacks/attack_gym_step.py`](attacks/attack_gym_step.py) - Gym-style `env.step(...)` example

## Guardrail Examples

These are local-only examples:

- [`guardrails/guardrail.py`](guardrails/guardrail.py)
- [`guardrails/guardrail_simple.py`](guardrails/guardrail_simple.py)
- [`guardrails/guardrail_optimal.py`](guardrails/guardrail_optimal.py)
- [`guardrails/guardrail_pattern.py`](guardrails/guardrail_pattern.py)
- [`guardrails/guardrail_perfect.py`](guardrails/guardrail_perfect.py)
- [`guardrails/guardrail_prompt_injection.py`](guardrails/guardrail_prompt_injection.py)
- [`guardrails/guardrail_promptguard.py`](guardrails/guardrail_promptguard.py)
- [`guardrails/guardrail_taint_tracking.py`](guardrails/guardrail_taint_tracking.py)

## Smoke-Test Scripts

- [`test_attack_submission.py`](test_attack_submission.py) - attack-only smoke test
- [`test_submission.py`](test_submission.py) - local attack+defense smoke test
- [`QUICK_START.md`](QUICK_START.md) - quick guide for the experimental example set

## Typical Workflows

### Attack-only

```bash
cp examples/attacks/attack_gym_step.py attack.py
python examples/test_attack_submission.py
python evaluation_redteam.py --submission attack.py --budget-s 60 --agent deterministic --env gym
```

### Local dual-track

```bash
cp examples/attacks/attack_working.py attack.py
cp examples/guardrails/guardrail_optimal.py guardrail.py
python examples/test_submission.py
zip submission.zip attack.py guardrail.py
python evaluation.py --submission_zip submission.zip --budget-s 60 --agent deterministic --env sandbox
```
