from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path
from typing import Final

REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
PACKAGE_ROOT: Final[Path] = REPO_ROOT / "aicomp_sdk"
INTEGRATION_TEST_ROOT: Final[Path] = REPO_ROOT / "tests" / "integration"
EXAMPLE_SUBMISSION_ROOTS: Final[tuple[Path, ...]] = (
    REPO_ROOT / "examples" / "attacks",
    REPO_ROOT / "examples" / "guardrails",
)

# This is an executable audit for the import-boundary hardening initiative.
# The map is intentionally explicit so new repo-bootstrap sites or embedded
# runners must be classified when they appear.
PATH_BOOTSTRAP_CLASSIFICATIONS: Final[dict[str, str]] = {
    "scripts/evaluate_all_guardrails.py": "repo_script_boundary",
    "scripts/evaluate_all_sample_attacks.py": "repo_script_boundary",
    "scripts/find_delete_chains.py": "repo_script_boundary",
    "scripts/find_exfil_chains.py": "repo_script_boundary",
    "scripts/find_secret_read_chains.py": "repo_script_boundary",
    "scripts/find_shell_chains.py": "repo_script_boundary",
    "scripts/goexplore_lpci_demo.py": "repo_script_boundary",
    "scripts/hooks_vs_baseline_comparison.py": "repo_script_boundary",
    "scripts/run_attack_openai.py": "repo_script_boundary",
    "scripts/smoke_check_local.py": "repo_script_boundary",
    "scripts/verify_findings_replay.py": "repo_script_boundary",
    "examples/test_attack_submission.py": "example_smoke_wrapper",
    "examples/test_submission.py": "example_smoke_wrapper",
}

MAIN_RUNNER_CLASSIFICATIONS: Final[dict[str, str]] = {
    "aicomp_sdk/attacks/baselines/attack_random.py": "library_demo_cleanup_target",
    "aicomp_sdk/attacks/baselines/attacker_goexplore.py": "library_demo_cleanup_target",
    "aicomp_sdk/cli/main.py": "supported_entrypoint",
    "aicomp_sdk/guardrails/hooks_examples.py": "library_demo_cleanup_target",
    "evaluation.py": "supported_entrypoint",
    "evaluation_redteam.py": "supported_entrypoint",
    "run_attack_openai.py": "compat_shim_boundary",
    "scripts/add_injection_sources.py": "repo_script_boundary",
    "scripts/count_injection_sources.py": "repo_script_boundary",
    "scripts/deduplicate_web_corpus.py": "repo_script_boundary",
    "scripts/evaluate_all_guardrails.py": "repo_script_boundary",
    "scripts/evaluate_all_sample_attacks.py": "repo_script_boundary",
    "scripts/generate_enhanced_fixtures.py": "repo_script_boundary",
    "scripts/generate_scale_fixtures_20k.py": "repo_script_boundary",
    "scripts/goexplore_lpci_demo.py": "repo_script_boundary",
    "scripts/goexplore_openai_demo.py": "repo_script_boundary",
    "scripts/hooks_vs_baseline_comparison.py": "repo_script_boundary",
    "scripts/minimal_breach_probe.py": "repo_script_boundary",
    "scripts/run_attack_openai.py": "repo_script_boundary",
    "scripts/scoring_balance_report.py": "repo_script_boundary",
    "scripts/smoke_check_local.py": "repo_script_boundary",
    "scripts/verify_findings_replay.py": "repo_script_boundary",
    "examples/test_attack_submission.py": "example_smoke_wrapper",
    "examples/test_submission.py": "example_smoke_wrapper",
}


def _iter_inventory_files() -> list[Path]:
    file_paths = [
        REPO_ROOT / "evaluation.py",
        REPO_ROOT / "evaluation_redteam.py",
        REPO_ROOT / "run_attack_openai.py",
    ]
    directory_paths = [
        REPO_ROOT / "aicomp_sdk",
        REPO_ROOT / "examples",
        REPO_ROOT / "scripts",
        REPO_ROOT / "tests" / "integration",
    ]
    for directory in directory_paths:
        file_paths.extend(sorted(directory.rglob("*.py")))
    return sorted(file_paths)


def _relative_path(path: Path) -> str:
    return str(path.relative_to(REPO_ROOT))


def _find_text_matches(*markers: str) -> set[str]:
    matches: set[str] = set()
    for path in _iter_inventory_files():
        contents = path.read_text()
        if any(marker in contents for marker in markers):
            matches.add(_relative_path(path))
    return matches


def _import_violations(
    root: Path, *, forbidden_roots: set[str]
) -> list[tuple[str, str, int]]:
    violations: list[tuple[str, str, int]] = []
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".", 1)[0] in forbidden_roots:
                        violations.append((_relative_path(path), alias.name, node.lineno))
            if isinstance(node, ast.ImportFrom) and node.module is not None:
                if node.module.split(".", 1)[0] in forbidden_roots:
                    violations.append((_relative_path(path), node.module, node.lineno))
    return violations


def _subprocess_env() -> dict[str, str]:
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    return env


def _example_submission_files() -> list[Path]:
    files: list[Path] = []
    for root in EXAMPLE_SUBMISSION_ROOTS:
        files.extend(sorted(root.glob("*.py")))
    return files


def test_sys_path_bootstrap_inventory_is_complete() -> None:
    actual = _find_text_matches("sys.path.insert", "sys.path.append")
    assert actual == set(PATH_BOOTSTRAP_CLASSIFICATIONS)


def test_main_runner_inventory_is_complete() -> None:
    actual = _find_text_matches('if __name__ == "__main__":', "if __name__ == '__main__':")
    assert actual == set(MAIN_RUNNER_CLASSIFICATIONS)


def test_package_code_contains_no_repo_bootstrap() -> None:
    package_bootstraps = {
        path for path in _find_text_matches("sys.path.insert", "sys.path.append")
        if path.startswith("aicomp_sdk/")
    }
    assert package_bootstraps == set()


def test_package_code_never_imports_tests_or_examples() -> None:
    assert _import_violations(PACKAGE_ROOT, forbidden_roots={"tests", "examples"}) == []


def test_integration_tests_never_import_examples() -> None:
    assert _import_violations(INTEGRATION_TEST_ROOT, forbidden_roots={"examples"}) == []


def test_example_submission_files_contain_no_repo_bootstrap() -> None:
    bootstrapped = [
        _relative_path(path)
        for path in _example_submission_files()
        if "sys.path.insert" in path.read_text() or "sys.path.append" in path.read_text()
    ]
    assert bootstrapped == []


def test_example_submission_files_have_no_inline_demo_runners() -> None:
    runners = [
        _relative_path(path)
        for path in _example_submission_files()
        if 'if __name__ == "__main__":' in path.read_text()
        or "if __name__ == '__main__':" in path.read_text()
    ]
    assert runners == []


def test_attacker_goexplore_imports_without_repo_root(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from aicomp_sdk.attacks.baselines.attacker_goexplore import AttackAlgorithm; "
            "print(AttackAlgorithm.__name__)",
        ],
        capture_output=True,
        cwd=tmp_path,
        env=_subprocess_env(),
        text=True,
        timeout=20,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "AttackAlgorithm"


def test_demo_library_modules_import_without_repo_root(tmp_path: Path) -> None:
    module_names = [
        "aicomp_sdk.attacks.baselines.attack_random",
        "aicomp_sdk.guardrails.hooks_examples",
    ]
    for module_name in module_names:
        result = subprocess.run(
            [sys.executable, "-c", f"import {module_name}; print({module_name}.__name__)"],
            capture_output=True,
            cwd=tmp_path,
            env=_subprocess_env(),
            text=True,
            timeout=20,
        )

        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == module_name


def test_evaluation_redteam_help_completes_from_outside_repo_root(tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "evaluation_redteam.py"), "--help"],
        capture_output=True,
        cwd=tmp_path,
        env=_subprocess_env(),
        text=True,
        timeout=20,
    )

    assert result.returncode == 0, result.stderr
    assert "usage:" in result.stdout.lower()
