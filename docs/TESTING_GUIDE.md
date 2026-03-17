# Testing Guide

Use this page when you need to validate repository changes locally or understand which checks matter in CI.

This guide focuses on practical validation order, focused local commands, and the current CI surface. It is not a full test inventory.

## Start With the Smallest Useful Check

The repository has both unit tests under `tests/unit/` and integration tests under `tests/integration/`.

Choose the smallest check that matches the kind of change you made.

### Docs or examples changed

Run:

```bash
cd docs && npm run docs:build
python examples/test_attack_submission.py
python examples/test_submission.py
```

Use the smoke script that matches the workflow you changed. `test_attack_submission.py` exercises the public-path attack flow. `test_submission.py` exercises the package dual-track flow.

### Attack-path code changed

Run:

```bash
pytest tests/unit/test_replay.py -v
pytest tests/unit/test_scoring.py -v
pytest tests/integration/test_baseline_performance.py -v
pytest tests/integration/test_verify_findings.py -v
```

### Guardrail or defense code changed

Run:

```bash
pytest tests/integration/test_optimal_guardrail.py -v
pytest tests/integration/test_prompt_injection_guardrail.py -v
pytest tests/integration/test_taint_tracking_guardrail.py -v
pytest tests/integration/test_dataflow_guardrail.py -v
```

### CLI or evaluator code changed

Run:

```bash
pytest tests/unit/test_cli_test_command.py -v
pytest tests/unit/test_cli_validate_command.py -v
pytest tests/unit/test_evaluation_redteam.py -v
pytest tests/unit/test_evaluation_legacy.py -v
pytest tests/unit/test_evaluation_env_selection.py -v
```

## Fast General Commands

Run all tests:

```bash
pytest tests/
```

Run unit tests:

```bash
pytest tests/unit/ -v
```

Run integration tests except the OpenAI-specific path:

```bash
pytest tests/integration/ -v -k "not openai"
```

Collect without running:

```bash
pytest --collect-only -q tests
```

## Current CI Surface

The GitHub workflows are split between blocking checks and informational checks.

### Blocking checks in CI

Current CI treats these as the most important checks to mirror locally:

```bash
pip install -e ".[dev]"
pytest tests/unit/ -v --cov=aicomp_sdk --cov-report=term-missing --cov-report=xml --cov-report=html
pytest tests/integration/ -v -k "not openai"
python -m build
twine check dist/*
flake8 aicomp_sdk --count --select=E9,F63,F7,F82 --show-source --statistics
flake8 aicomp_sdk --count --max-complexity=10 --max-line-length=127 --statistics
black --check --diff aicomp_sdk
isort --check-only --diff aicomp_sdk
```

### Informational or non-blocking checks in CI

These currently run in CI, but they are configured as advisory or continue-on-error checks:

```bash
mypy aicomp_sdk --show-error-codes --pretty
bandit -r aicomp_sdk
radon cc aicomp_sdk -a -nb
radon mi aicomp_sdk -s
pylint aicomp_sdk --exit-zero
pydocstyle aicomp_sdk --count
```

The repo also runs Markdown link checking in CI through `.github/workflows/lint.yml`.

## Focused Test Areas

Use these clusters when you want deeper validation in one part of the package.

### Environment and scoring behavior

```bash
pytest tests/unit/test_env.py -v
pytest tests/unit/test_gym_env.py -v
pytest tests/unit/test_predicates.py -v
pytest tests/unit/test_scoring.py -v
pytest tests/unit/test_replay.py -v
```

### Attack behavior

```bash
pytest tests/integration/test_baseline_performance.py -v
pytest tests/integration/test_minimal_breach.py -v
pytest tests/integration/test_verify_findings.py -v
```

### Guardrail behavior

```bash
pytest tests/integration/test_optimal_guardrail.py -v
pytest tests/integration/test_prompt_injection_guardrail.py -v
pytest tests/integration/test_taint_tracking_guardrail.py -v
pytest tests/integration/test_dataflow_guardrail.py -v
```

## Environment Notes

### `gymnasium`

`GymAttackEnv` tests require `gymnasium` to be importable.

### OpenAI-backed tests

OpenAI-specific paths require `OPENAI_API_KEY` or rely on offline fixtures where the test explicitly provides them.

### Packaged fixtures

Evaluators can resolve packaged fixtures automatically. Direct environment tests usually point at repository fixtures explicitly.

## Recommended Local Validation Order

1. run the smallest focused check for the subsystem you changed
2. run the relevant smoke script if docs or examples changed
3. run broader unit or integration suites if you changed shared behavior
4. run the blocking CI commands before opening or updating a PR
5. run advisory checks if your change touches typing, security-sensitive code, or documentation quality

## References

- [`GETTING_STARTED.md`](GETTING_STARTED.md)
- [`ATTACKS_GUIDE.md`](ATTACKS_GUIDE.md)
- [`GUARDRAILS_GUIDE.md`](GUARDRAILS_GUIDE.md)
- [`API_REFERENCE.md`](API_REFERENCE.md)
