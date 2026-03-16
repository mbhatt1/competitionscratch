# GitHub Workflows

This directory contains the repository's GitHub Actions workflows and the minimal runbook for maintaining them.

The previous version of this document mixed useful operator guidance with stale assumptions. This version keeps the practical setup and release notes, but aligns them with the workflow files that actually exist today.

## Workflow Files

- [`ci.yml`](ci.yml) runs the Python test matrix, unit tests with coverage, non-OpenAI integration tests, package builds, and fixture packaging checks.
- [`lint.yml`](lint.yml) runs formatting, linting, import-order, type-checking, security, complexity, pylint, and docs checks.
- [`deploy-docs.yml`](deploy-docs.yml) builds the VitePress docs site and deploys it to GitHub Pages.
- [`publish.yml`](publish.yml) builds distributions on version tags, publishes to PyPI, and creates a GitHub Release.

## Current Behavior

### `ci.yml`

Current behavior:

- triggers on pushes and pull requests for `main`, `master`, and `develop`
- tests Python `3.9`, `3.10`, and `3.11`
- installs the package with `.[dev]`
- runs unit tests with coverage
- runs non-OpenAI integration tests
- uploads coverage artifacts from Python `3.11`
- builds the package and verifies packaged fixtures in the wheel

### `lint.yml`

Current behavior:

- triggers on pushes and pull requests for `main`, `master`, and `develop`
- runs `flake8`, `black --check`, and `isort --check-only` as blocking checks
- runs `mypy`, `bandit`, `radon`, `pylint`, and `pydocstyle` as non-blocking quality signals
- checks Markdown links using `.github/markdown-link-check-config.json`
- fails the `quality-gate` job if the critical lint job fails

### `deploy-docs.yml`

Current behavior:

- triggers on pushes to `master` that touch `docs/**` or the workflow file, plus manual dispatch
- installs docs dependencies from [`docs/package.json`](../../docs/package.json)
- runs `npm run docs:build`
- uploads `docs/.vitepress/dist` and deploys it to GitHub Pages

### `publish.yml`

Current behavior:

- triggers on tags matching `v*.*.*` and `v*`
- builds the source distribution and wheel
- runs `twine check dist/*`
- publishes to PyPI using the `PYPI_API_TOKEN` secret
- creates a GitHub Release and attaches the built artifacts
- generates release notes from the tag and optionally from `CHANGELOG.md` if that file exists

## Repository Setup

### PyPI publishing

Set this repository secret before using [`publish.yml`](publish.yml):

- `PYPI_API_TOKEN`

The workflow comments still mention trusted publishing, but the current job explicitly passes `password: ${{ secrets.PYPI_API_TOKEN }}`. If the workflow is migrated to pure trusted publishing later, update both the workflow and this README together.

### Docs deployment

For [`deploy-docs.yml`](deploy-docs.yml):

- GitHub Pages must be enabled for the repository
- the `github-pages` environment used by the deploy job must be available

## Useful Local Equivalents

### Test and build flow

```bash
pip install -e ".[dev]"
pip install build twine
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

## Verifying Workflow Changes

When editing workflow YAML:

1. run the local equivalent commands first
2. make a small branch-local change and open a PR
3. confirm the expected workflows trigger
4. check the artifacts, release behavior, or Pages behavior that the workflow is supposed to produce

For publishing changes, avoid discovering mistakes on a real release tag. Validate the build and `twine check` locally first.

## Release Process

Use this when you actually want the repository workflows to publish a release.

### 1. Update package version

Edit [`pyproject.toml`](../../pyproject.toml) and bump `[project].version`.

### 2. Sanity-check the release locally

```bash
pip install -e ".[dev]"
pip install build twine
python -m build
twine check dist/*
```

### 3. Commit the release prep

```bash
git add pyproject.toml
git commit -m "chore: bump version to X.Y.Z"
git push origin <branch>
```

### 4. Create and push the release tag

```bash
git tag -a vX.Y.Z -m "Release version X.Y.Z"
git push origin vX.Y.Z
```

### 5. Monitor the publish workflow

Confirm that:

- `build-package` succeeds
- `publish-to-pypi` succeeds
- `create-github-release` succeeds
- the package appears on PyPI
- the GitHub Release is created with attached artifacts

## Troubleshooting

### CI passes locally but fails in Actions

Check:

- Python version differences across `3.9`, `3.10`, and `3.11`
- undeclared dependencies in `pyproject.toml`
- tests that accidentally depend on local state

### PyPI publish fails

Check:

- `PYPI_API_TOKEN` exists and is valid
- the target version was not already published
- the built distributions pass `twine check dist/*`

### Docs deploy fails

Check:

- the workflow still targets the intended branch (`master` today)
- `docs/package.json` still contains the docs build dependencies
- `docs/.vitepress/dist` is still the correct output path
- GitHub Pages is enabled for the repository

### Lint docs drift from workflow reality

This file should describe the workflow YAML as it exists, not the workflow YAML as it used to exist or might exist later. If you change a workflow trigger, step, secret, artifact name, or deploy target, update this README in the same change.

## Notes

- some quality checks in [`lint.yml`](lint.yml) are intentionally non-blocking
- the Markdown link checker config lives at [`.github/markdown-link-check-config.json`](../markdown-link-check-config.json)
- [`publish.yml`](publish.yml) optionally reads `CHANGELOG.md`, but the repository does not currently require that file to exist for releases
