# Examples Quick Start

Use this page when you want the shortest path through the curated example set.

This quickstart focuses on three jobs:

- public-path attack iteration
- package guardrail-only testing
- package dual-track attack+guardrail testing

The example files themselves are submission examples. When you want to execute them from the repo, use the smoke wrappers on this page or the package CLI and evaluator commands.

The standalone evaluator defaults to a short terminal summary. Add `--verbosity progress` for package-owned progress messages, plus `--save-transcript`, `--save-framework-events`, and `--save-agent-debug` when you want `transcript.log`, `framework.jsonl`, and `agent-debug.jsonl` under `--artifacts-dir`.

## 1. Public-Path Attack Example

Run the canonical attack example smoke test:

```bash
python examples/test_attack_submission.py
```

At the default short budget, this is a compatibility smoke test. It may legitimately report `0` findings.

When you want to run the public contract directly, copy the example into the required filename:

```bash
cp examples/attacks/attack.py attack.py
aicomp evaluate redteam attack.py --budget-s 60 --agent deterministic --env sandbox
```

Why the copy step matters: the public Kaggle evaluator requires the submission file to be named `attack.py`.

## 2. Package Guardrail-Only Example

Use the canonical guardrail example directly:

```bash
aicomp validate defense examples/guardrails/guardrail.py
aicomp test defense examples/guardrails/guardrail.py --budget-s 60 --agent deterministic
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
aicomp evaluate dual submission.zip --budget-s 60 --agent deterministic --env sandbox
```

## Advanced and Experimental Examples

Use these only after the canonical paths are working:

- [`attacks/attack.py`](attacks/attack.py) - canonical high-level attack example
- [`attacks/attack_gym_step.py`](attacks/attack_gym_step.py) - minimal Gym-style `env.step(...)` attack example
- [`attacks/attack_working.py`](attacks/attack_working.py) - broader deterministic attack variant
- [`attacks/attack_goexplore_working.py`](attacks/attack_goexplore_working.py) - Go-Explore variant with a broader demo runner
- [`attacks/attack_simple.py`](attacks/attack_simple.py) - simple fixed-prompt attack variant
- [`attacks/attack_goexplore_lpci.py`](attacks/attack_goexplore_lpci.py) - Go-Explore attacker plus explicit local LPCI hook-registry builder
- [`hooks/complete_attack_scenario.py`](hooks/complete_attack_scenario.py) - composed local compromised-environment hook fixture
- [`guardrails/guardrail_pattern.py`](guardrails/guardrail_pattern.py) - stateless pattern-based guardrail
- [`guardrails/guardrail_prompt_injection.py`](guardrails/guardrail_prompt_injection.py) - smaller persistent-taint guardrail
- [`guardrails/guardrail_simple.py`](guardrails/guardrail_simple.py) - simple rule-based guardrail variant
- [`guardrails/guardrail_promptguard.py`](guardrails/guardrail_promptguard.py) - Prompt-Guard-backed example with heavier model-loading costs
- [`../scripts/goexplore_lpci_demo.py`](../scripts/goexplore_lpci_demo.py) - repo-local demo wrapper for the experimental LPCI attack example

## Recommended Order

1. Start with [`attacks/attack.py`](attacks/attack.py) for the cleanest high-level public-path attack example.
2. Use [`attacks/attack_gym_step.py`](attacks/attack_gym_step.py) only when you specifically want the Gym-style `env.step(...)` surface.
3. Pair [`attacks/attack.py`](attacks/attack.py) with [`guardrails/guardrail.py`](guardrails/guardrail.py) for the canonical package-local dual-track example.
4. Add stronger or experimental variants only when you are comparing strategies rather than learning the package surface.

## Related Docs

- [`../docs/GETTING_STARTED.md`](../docs/GETTING_STARTED.md)
- [`../docs/KAGGLE_REDTEAM_GUIDE.md`](../docs/KAGGLE_REDTEAM_GUIDE.md)
- [`../docs/ATTACKS_GUIDE.md`](../docs/ATTACKS_GUIDE.md)
- [`../docs/GUARDRAILS_GUIDE.md`](../docs/GUARDRAILS_GUIDE.md)
