# Examples Quick Start

Use this page when you want the shortest path through the curated example set.

This quickstart focuses on three jobs:

- public-path attack iteration
- package guardrail-only testing
- package dual-track attack+guardrail testing

The example files themselves are submission examples. When you want to execute them from the repo, use the smoke wrappers on this page or the package CLI and evaluator commands.

## 1. Public-Path Attack Example

Run the canonical attack example smoke test:

```bash
python examples/test_attack_submission.py
```

At the default short budget, this is a compatibility smoke test. It may legitimately report `0` findings.

When you want to run the public contract directly, copy the example into the required filename:

```bash
cp examples/attacks/attack_gym_step.py attack.py
python evaluation_redteam.py --submission attack.py --budget-s 60 --agent deterministic --env gym
```

Why the copy step matters: the public Kaggle evaluator requires the submission file to be named `attack.py`.

## 2. Package Guardrail-Only Example

Use the canonical guardrail example directly:

```bash
aicomp validate examples/guardrails/guardrail.py --type guardrail
aicomp test examples/guardrails/guardrail.py --track defense --quick --agent deterministic
```

Switch to [`guardrails/guardrail_optimal.py`](guardrails/guardrail_optimal.py) when you want a more aggressive blocking policy, or [`guardrails/guardrail_taint_tracking.py`](guardrails/guardrail_taint_tracking.py) when you want a stateful session-taint design.

## 3. Package Dual-Track Example

Run the canonical package-local pair smoke test:

```bash
python examples/test_submission.py
```

When you want to package the pair for the standalone dual-track evaluator:

```bash
cp examples/attacks/attack.py attack.py
cp examples/guardrails/guardrail.py guardrail.py
zip submission.zip attack.py guardrail.py
python evaluation.py --submission_zip submission.zip --budget-s 60 --agent deterministic --env sandbox
```

## Advanced and Experimental Examples

Use these only after the canonical paths are working:

- [`attacks/attack.py`](attacks/attack.py) - canonical package-local Go-Explore attack
- [`attacks/attack_working.py`](attacks/attack_working.py) - broader deterministic attack variant
- [`attacks/attack_goexplore_working.py`](attacks/attack_goexplore_working.py) - Go-Explore variant with a broader demo runner
- [`attacks/attack_simple.py`](attacks/attack_simple.py) - experimental hook-based attack
- [`attacks/attack_goexplore_lpci.py`](attacks/attack_goexplore_lpci.py) - experimental Go-Explore plus hook attack
- [`guardrails/guardrail_pattern.py`](guardrails/guardrail_pattern.py) - stateless pattern-based guardrail
- [`guardrails/guardrail_prompt_injection.py`](guardrails/guardrail_prompt_injection.py) - smaller persistent-taint guardrail
- [`guardrails/guardrail_simple.py`](guardrails/guardrail_simple.py) - experimental hook-based guardrail
- [`guardrails/guardrail_promptguard.py`](guardrails/guardrail_promptguard.py) - Prompt-Guard-backed example with heavier model-loading costs
- [`../scripts/goexplore_lpci_demo.py`](../scripts/goexplore_lpci_demo.py) - repo-local demo wrapper for the experimental LPCI attack example

## Recommended Order

1. Start with [`attacks/attack_gym_step.py`](attacks/attack_gym_step.py) for the cleanest public-path attack example.
2. Move to [`attacks/attack.py`](attacks/attack.py) and [`guardrails/guardrail.py`](guardrails/guardrail.py) for the canonical package-local pair.
3. Add stronger or experimental variants only when you are comparing strategies rather than learning the package surface.

## Related Docs

- [`../docs/GETTING_STARTED.md`](../docs/GETTING_STARTED.md)
- [`../docs/KAGGLE_REDTEAM_GUIDE.md`](../docs/KAGGLE_REDTEAM_GUIDE.md)
- [`../docs/ATTACKS_GUIDE.md`](../docs/ATTACKS_GUIDE.md)
- [`../docs/GUARDRAILS_GUIDE.md`](../docs/GUARDRAILS_GUIDE.md)
