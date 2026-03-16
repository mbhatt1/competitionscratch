# Testing Guide

This guide describes the current repository test surface, how CI exercises it, and the most useful local commands.

## Current Test Layout

The repository currently contains:

- unit tests under `tests/unit/`
- integration tests under `tests/integration/`

Representative unit-test coverage:

- attack and evaluator contracts
- CLI commands (`validate`, `test`, result consumers)
- environments (`SandboxEnv`, `GymAttackEnv`, diagnostics env)
- agents (`openai`, `gpt_oss`, `gemma`, HF chat-template)
- tools, tool handlers, and tool schemas
- scoring, predicates, trace export, replay, and runtime history

Representative integration-test coverage:

- baseline attack performance
- baseline defense behavior
- optimal / taint-tracking / prompt-injection guardrails
- dataflow guardrail behavior
- minimal breach examples
- hooks-vs-baseline comparisons

## Current Suite Size

In the current repository state, `pytest --collect-only -q tests` collects hundreds of tests.

One useful snapshot from this workspace:

- `460` collected tests
- `tests/unit/test_gym_env.py` is skipped if `gymnasium` is unavailable in the active environment

Treat those numbers as a moving snapshot, not a permanent contract.

## Fast Local Commands

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

Run a single file:

```bash
pytest tests/unit/test_cli_test_command.py -v
```

Collect without running:

```bash
pytest --collect-only -q tests
```

## Commands Used in CI

The current GitHub workflows run checks that are worth mirroring locally:

### From `.github/workflows/ci.yml`

```bash
pip install -e ".[dev]"
pytest tests/unit/ -v --cov=aicomp_sdk --cov-report=term-missing --cov-report=xml --cov-report=html
pytest tests/integration/ -v -k "not openai"
python -m build
twine check dist/*
```

### From `.github/workflows/lint.yml`

```bash
flake8 aicomp_sdk --count --select=E9,F63,F7,F82 --show-source --statistics
flake8 aicomp_sdk --count --max-complexity=10 --max-line-length=127 --statistics
black --check --diff aicomp_sdk
isort --check-only --diff aicomp_sdk
mypy aicomp_sdk --show-error-codes --pretty
```

## Useful Focus Areas

### CLI and evaluator behavior

Run:

```bash
pytest tests/unit/test_cli_test_command.py -v
pytest tests/unit/test_cli_validate_command.py -v
pytest tests/unit/test_evaluation_redteam.py -v
pytest tests/unit/test_evaluation_legacy.py -v
pytest tests/unit/test_evaluation_env_selection.py -v
```

### Environment and scoring behavior

Run:

```bash
pytest tests/unit/test_env.py -v
pytest tests/unit/test_gym_env.py -v
pytest tests/unit/test_predicates.py -v
pytest tests/unit/test_scoring.py -v
pytest tests/unit/test_replay.py -v
```

### Guardrail behavior

Run:

```bash
pytest tests/integration/test_optimal_guardrail.py -v
pytest tests/integration/test_prompt_injection_guardrail.py -v
pytest tests/integration/test_taint_tracking_guardrail.py -v
pytest tests/integration/test_dataflow_guardrail.py -v
```

### Attack behavior

Run:

```bash
pytest tests/integration/test_baseline_performance.py -v
pytest tests/integration/test_minimal_breach.py -v
pytest tests/integration/test_verify_findings.py -v
```

## Example Smoke Tests

Repository examples also provide quick end-to-end checks:

```bash
python examples/test_attack_submission.py
python examples/test_submission.py
```

The first targets the attack-only path. The second exercises the broader local attack+defense workflow.

## Test Environment Notes

### `gymnasium`

`GymAttackEnv` tests require `gymnasium` to be importable.

### OpenAI-backed tests

OpenAI-specific paths require `OPENAI_API_KEY` or use offline fixtures where the test explicitly provides them.

### Packaged fixtures

Evaluators can resolve packaged fixtures automatically. Direct environment tests usually point at the repository fixtures explicitly.

## Documentation Validation

The repo also checks Markdown links in CI. Relevant workflow pieces:

- `.github/workflows/lint.yml`
- `.github/markdown-link-check-config.json`

If you change docs substantially, it is worth verifying:

- relative links
- example filenames
- CLI flags
- package names and imports

## Recommended Local Validation Order

1. run focused unit tests for the files you changed
2. run `pytest --collect-only -q tests` if you changed discovery-sensitive files
3. run the relevant example smoke script if docs or examples changed
4. run the lint/typecheck commands if you changed Python code

## References

- [`GETTING_STARTED.md`](GETTING_STARTED.md)
- [`ATTACKS_GUIDE.md`](ATTACKS_GUIDE.md)
- [`GUARDRAILS_GUIDE.md`](GUARDRAILS_GUIDE.md)
