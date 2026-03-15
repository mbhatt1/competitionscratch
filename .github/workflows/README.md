# GitHub Workflows

This directory contains the repository's GitHub Actions workflows.

## Current Workflow Files

- [`ci.yml`](ci.yml) - test matrix, integration tests, build verification, coverage artifacts
- [`lint.yml`](lint.yml) - linting, formatting, typing, security, docs checks
- [`deploy-docs.yml`](deploy-docs.yml) - builds the VitePress site and deploys it to GitHub Pages
- [`publish.yml`](publish.yml) - builds and publishes the package on version tags

## What Each Workflow Does

### `ci.yml`

Current behavior:

- runs on pushes and pull requests for `main`, `master`, and `develop`
- tests Python `3.9`, `3.10`, and `3.11`
- installs the package with `.[dev]`
- runs unit tests with coverage
- runs non-OpenAI integration tests
- builds the package and checks packaged fixtures

### `lint.yml`

Current behavior:

- runs on pushes and pull requests for `main`, `master`, and `develop`
- runs `flake8`, `black --check`, `isort --check-only`
- runs `mypy` as a non-blocking check
- runs `bandit`, `radon`, and `pylint` as additional quality signals
- runs `pydocstyle`
- runs Markdown link checking using `.github/markdown-link-check-config.json`

### `deploy-docs.yml`

Current behavior:

- runs on pushes to `master` that touch `docs/**` or the workflow file
- installs docs dependencies from `docs/package.json`
- runs `npm run docs:build`
- deploys `docs/.vitepress/dist` to GitHub Pages

### `publish.yml`

Current behavior:

- runs on tags matching `v*.*.*` and `v*`
- builds the source distribution and wheel
- runs `twine check dist/*`
- publishes to PyPI using the `PYPI_API_TOKEN` secret
- creates a GitHub Release with the built artifacts

## Useful Local Equivalents

### Test and build flow

```bash
pip install -e ".[dev]"
pytest tests/unit/ -v --cov=aicomp_sdk --cov-report=term-missing --cov-report=xml --cov-report=html
pytest tests/integration/ -v -k "not openai"
python -m build
twine check dist/*
```

### Lint and typing flow

```bash
flake8 aicomp_sdk --count --select=E9,F63,F7,F82 --show-source --statistics
flake8 aicomp_sdk --count --max-complexity=10 --max-line-length=127 --statistics
black --check --diff aicomp_sdk
isort --check-only --diff aicomp_sdk
mypy aicomp_sdk --show-error-codes --pretty
```

### Docs flow

```bash
cd docs
npm install
npm run docs:build
```

## Required Repository Configuration

### For package publishing

Set the repository secret:

- `PYPI_API_TOKEN`

### For docs deployment

GitHub Pages must be enabled for the repository environment used by `deploy-docs.yml`.

## Notes

- Some quality checks in `lint.yml` are intentionally non-blocking.
- The Markdown link checker has its own config file at `.github/markdown-link-check-config.json`.
- The publish workflow comments mention trusted publishing, but the current workflow still passes `PYPI_API_TOKEN` explicitly.
