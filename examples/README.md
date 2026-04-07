# Examples

Use this directory when you want runnable examples for the current package surface.

The package supports attack-only, guardrail-only, and dual-track workflows. The public Kaggle path still requires `attack.py` as the submission filename, so attack examples become public-path compatible when you copy or rename them to `attack.py`.

The files under `attacks/` and `guardrails/` are clean submission examples, not standalone CLI programs. Use the smoke wrappers in this directory, `aicomp validate`, `aicomp test`, or `aicomp evaluate` when you want to run them locally.

The standalone evaluator defaults to a short terminal summary. Add `--verbosity progress` for package-owned progress messages, plus `--save-transcript`, `--save-framework-events`, and `--save-agent-debug` when you want `transcript.log`, `framework.jsonl`, and `agent-debug.jsonl` under `--artifacts-dir`.

## Choose a Starting Point

### I want the cleanest public-path attack example

Start with:

- [`attacks/attack.py`](attacks/attack.py)
- [`test_attack_submission.py`](test_attack_submission.py)
- [`../docs/GETTING_STARTED.md`](../docs/GETTING_STARTED.md)
- [`../docs/KAGGLE_REDTEAM_GUIDE.md`](../docs/KAGGLE_REDTEAM_GUIDE.md)

Use this path if:

- you want the canonical current `AttackAlgorithm` example
- you want the high-level `evaluate_redteam(...)` smoke path
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
- [`hooks/complete_attack_scenario.py`](hooks/complete_attack_scenario.py)
- [`guardrails/guardrail_simple.py`](guardrails/guardrail_simple.py)
- [`guardrails/guardrail_promptguard.py`](guardrails/guardrail_promptguard.py)
- [`../scripts/goexplore_lpci_demo.py`](../scripts/goexplore_lpci_demo.py)

Use this path if:

- you want to run a local harness-owned LPCI hook demo
- you want to study Prompt-Guard-backed filtering
- you do not need the simplest starting point

`guardrail_promptguard.py` is materially heavier than the rest of the set because it loads a transformer classifier at runtime.

## Canonical Examples

- [`attacks/attack.py`](attacks/attack.py) - canonical high-level attack example
- [`attacks/attack_gym_step.py`](attacks/attack_gym_step.py) - minimal Gym-style `env.step(...)` attack example
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

- [`attacks/attack_simple.py`](attacks/attack_simple.py) - simple fixed-prompt attack experiment
- [`attacks/attack_goexplore_lpci.py`](attacks/attack_goexplore_lpci.py) - Go-Explore attacker plus explicit local LPCI hook-registry builder
- [`hooks/vector_store_poisoning.py`](hooks/vector_store_poisoning.py) - local CONTEXT_BUILD vector-store poisoning fixture
- [`hooks/tool_arg_rewrite.py`](hooks/tool_arg_rewrite.py) - local PRE_TOOL_CALL tool-argument rewrite fixture
- [`hooks/payload_injection.py`](hooks/payload_injection.py) - local POST_TOOL_CALL payload injection fixture
- [`hooks/triggered_guardrail_context.py`](hooks/triggered_guardrail_context.py) - local PRE_GUARDRAIL trigger/context mutation fixture
- [`hooks/memory_state.py`](hooks/memory_state.py) - local MEMORY_STORE state-tracking fixture
- [`hooks/detection.py`](hooks/detection.py) - local outbound-exfil detection fixture
- [`hooks/complete_attack_scenario.py`](hooks/complete_attack_scenario.py) - composed local compromised-environment fixture
- [`guardrails/guardrail_simple.py`](guardrails/guardrail_simple.py) - simple rule-based guardrail experiment
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
cp examples/attacks/attack.py attack.py
aicomp evaluate redteam attack.py --budget-s 60 --agent deterministic --env sandbox
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
