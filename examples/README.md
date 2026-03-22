# Examples

Use this directory when you want runnable examples for the current package surface.

The package supports attack-only, guardrail-only, and dual-track workflows. The public Kaggle path still requires `attack.py` as the submission filename, so attack examples become public-path compatible when you copy or rename them to `attack.py`.

The files under `attacks/` and `guardrails/` are clean submission examples, not standalone CLI programs. Use the smoke wrappers in this directory, `aicomp validate`, `aicomp test`, or `aicomp evaluate` when you want to run them locally.

The standalone evaluator defaults to a short terminal summary. Add `--verbosity progress` for package-owned progress messages, plus `--save-transcript`, `--save-framework-events`, and `--save-agent-debug` when you want `transcript.log`, `framework.jsonl`, and `agent-debug.jsonl` under `--artifacts-dir`.

## Choose a Starting Point

### I want the cleanest public-path attack example

Start with:

- [`attacks/attack_gym_step.py`](attacks/attack_gym_step.py)
- [`test_attack_submission.py`](test_attack_submission.py)
- [`../docs/GETTING_STARTED.md`](../docs/GETTING_STARTED.md)
- [`../docs/KAGGLE_REDTEAM_GUIDE.md`](../docs/KAGGLE_REDTEAM_GUIDE.md)

Use this path if:

- you want the shortest current `AttackAlgorithm` example
- you want a Gym-style `env.step(...)` attack
- you are building toward the public Kaggle `attack.py` contract

### I want a canonical package-local attack + guardrail pair

Start with:

- [`attacks/attack.py`](attacks/attack.py)
- [`guardrails/guardrail.py`](guardrails/guardrail.py)
- [`test_submission.py`](test_submission.py)

Use this path if:

- you want a package-local dual-track pair with current contracts
- you want a concise smoke test before packaging `submission.zip`
- you want examples that map cleanly to `aicomp evaluate dual`

### I want stronger or more specialized package examples

Start with:

- [`attacks/attack_working.py`](attacks/attack_working.py)
- [`attacks/attack_goexplore_working.py`](attacks/attack_goexplore_working.py)
- [`guardrails/guardrail_optimal.py`](guardrails/guardrail_optimal.py)
- [`guardrails/guardrail_pattern.py`](guardrails/guardrail_pattern.py)
- [`guardrails/guardrail_taint_tracking.py`](guardrails/guardrail_taint_tracking.py)
- [`guardrails/guardrail_prompt_injection.py`](guardrails/guardrail_prompt_injection.py)

Use this path if:

- you want a stronger local search baseline than the minimal Gym example
- you want to compare stateless versus stateful guardrail strategies
- you are experimenting with package-only attack or defense workflows

### I want experimental or heavyweight examples

Start with:

- [`attacks/attack_simple.py`](attacks/attack_simple.py)
- [`attacks/attack_goexplore_lpci.py`](attacks/attack_goexplore_lpci.py)
- [`guardrails/guardrail_simple.py`](guardrails/guardrail_simple.py)
- [`guardrails/guardrail_promptguard.py`](guardrails/guardrail_promptguard.py)

Use this path if:

- you want to experiment with hook-based attacks or defenses
- you want to study Prompt-Guard-backed filtering
- you do not need the simplest starting point

`guardrail_promptguard.py` is materially heavier than the rest of the set because it loads a transformer classifier at runtime.

## Canonical Examples

- [`attacks/attack_gym_step.py`](attacks/attack_gym_step.py) - shortest current attack example for Gym-style red-team evaluation
- [`attacks/attack.py`](attacks/attack.py) - canonical package-local Go-Explore-style attack example
- [`guardrails/guardrail.py`](guardrails/guardrail.py) - canonical context-aware guardrail using the current `decide(...)` context

## Advanced Package-Local Examples

- [`attacks/attack_working.py`](attacks/attack_working.py) - broader deterministic prompt bank over the same search pattern
- [`attacks/attack_goexplore_working.py`](attacks/attack_goexplore_working.py) - Go-Explore variant with a broader demo runner
- [`guardrails/guardrail_optimal.py`](guardrails/guardrail_optimal.py) - aggressive recent-taint plus sensitive-target blocking
- [`guardrails/guardrail_pattern.py`](guardrails/guardrail_pattern.py) - stateless pattern-based guardrail
- [`guardrails/guardrail_taint_tracking.py`](guardrails/guardrail_taint_tracking.py) - stateful session-taint example
- [`guardrails/guardrail_prompt_injection.py`](guardrails/guardrail_prompt_injection.py) - smaller persistent-taint prompt-injection guardrail
- [`guardrails/guardrail_perfect.py`](guardrails/guardrail_perfect.py) - didactic strict-isolation baseline

## Experimental Examples

- [`attacks/attack_simple.py`](attacks/attack_simple.py) - hook-based attack experiment
- [`attacks/attack_goexplore_lpci.py`](attacks/attack_goexplore_lpci.py) - Go-Explore plus LPCI-style hook experiment
- [`guardrails/guardrail_simple.py`](guardrails/guardrail_simple.py) - hook-based guardrail experiment
- [`guardrails/guardrail_promptguard.py`](guardrails/guardrail_promptguard.py) - transformer-backed Prompt-Guard example with heavier runtime costs
- [`../scripts/goexplore_lpci_demo.py`](../scripts/goexplore_lpci_demo.py) - repo-local demo wrapper for the experimental LPCI attack example

## Smoke Tests

- [`test_attack_submission.py`](test_attack_submission.py) - concise attack-only smoke test for an example or submission file
- [`test_submission.py`](test_submission.py) - concise package dual-track smoke test for an attack/guardrail pair
- [`QUICK_START.md`](QUICK_START.md) - task-first quickstart for the curated example set

## Typical Workflows

### Public-path attack example

Run the example smoke test first:

```bash
python examples/test_attack_submission.py
```

At the default short budget, this smoke test verifies current evaluator compatibility. It may legitimately report `0` findings.

Then copy the example into the public submission shape:

```bash
cp examples/attacks/attack_gym_step.py attack.py
aicomp evaluate redteam attack.py --budget-s 60 --agent deterministic --env gym
```

### Package guardrail-only example

Validate and test the example directly:

```bash
aicomp validate defense examples/guardrails/guardrail.py
aicomp test defense examples/guardrails/guardrail.py --budget-s 60 --agent deterministic
```

### Package dual-track example

Run the example pair smoke test first:

```bash
python examples/test_submission.py
```

Then package the canonical pair for the standalone dual-track evaluator:

```bash
cp examples/attacks/attack.py attack.py
cp examples/guardrails/guardrail.py guardrail.py
zip submission.zip attack.py guardrail.py
aicomp evaluate dual submission.zip --budget-s 60 --agent deterministic --env sandbox
```
