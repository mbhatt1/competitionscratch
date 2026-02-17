#!/usr/bin/env python3
"""Local smoke check for submission + evaluator contract integrity.

This script runs a fast deterministic check that should pass before pushing:
1. Validate root submission files (`attack.py`, `guardrail.py`).
2. Run focused unit tests for attack-evaluation contract/scoring.
3. Build a temporary submission zip from root files.
4. Execute `evaluation.py` end-to-end and verify output artifacts.

Optional `--extended` runs longer report scripts as an extra sanity pass.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any


def _require_file(path: Path) -> None:
    if not path.exists():
        raise FileNotFoundError(f"Required file missing: {path}")


def _run(cmd: list[str], *, cwd: Path, env: dict[str, str], quiet: bool = False) -> None:
    print(f"$ {' '.join(cmd)}")
    if not quiet:
        subprocess.run(cmd, cwd=str(cwd), env=env, check=True)
        return

    proc = subprocess.run(
        cmd,
        cwd=str(cwd),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if proc.returncode != 0:
        print(proc.stdout)
        raise subprocess.CalledProcessError(proc.returncode, cmd)


def _build_submission_zip(repo_root: Path, zip_path: Path) -> None:
    attack_file = repo_root / "attack.py"
    guardrail_file = repo_root / "guardrail.py"
    _require_file(attack_file)
    _require_file(guardrail_file)

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.write(attack_file, arcname="attack.py")
        zf.write(guardrail_file, arcname="guardrail.py")


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Expected JSON object in {path}")
    return payload


def _load_module(module_path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module spec from {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _assert_submission_entrypoints(repo_root: Path) -> None:
    from aicomp_sdk.attacks import AttackAlgorithmBase

    attack_mod = _load_module(repo_root / "attack.py", "smoke_attack")
    guardrail_mod = _load_module(repo_root / "guardrail.py", "smoke_guardrail")

    if not hasattr(attack_mod, "AttackAlgorithm"):
        raise RuntimeError("attack.py must export AttackAlgorithm")
    if not hasattr(guardrail_mod, "Guardrail"):
        raise RuntimeError("guardrail.py must export Guardrail")
    if not issubclass(attack_mod.AttackAlgorithm, AttackAlgorithmBase):
        raise RuntimeError("attack.py AttackAlgorithm must inherit AttackAlgorithmBase")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run local smoke checks for competition SDK.")
    parser.add_argument(
        "--seconds",
        type=float,
        default=20.0,
        help="Total evaluation seconds budget for smoke run (default: 20).",
    )
    parser.add_argument(
        "--extended",
        action="store_true",
        help="Also run longer scripts/evaluate_all_sample_attacks.py and scripts/evaluate_all_guardrails.py.",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    venv_python = repo_root / ".venv" / "bin" / "python"
    venv_cli = repo_root / ".venv" / "bin" / "aicomp"
    python_bin = str(venv_python if venv_python.exists() else Path(sys.executable))
    cli_cmd = [str(venv_cli)] if venv_cli.exists() else [python_bin, "-m", "aicomp_sdk.cli.main"]

    env = os.environ.copy()
    # Keep smoke checks deterministic and offline by default.
    env.pop("OPENAI_API_KEY", None)
    env.pop("GPT_OSS_MODEL_PATH", None)
    env["PYTHONPATH"] = str(repo_root)

    _run(
        [*cli_cmd, "validate", "attack.py", "--type", "attack"],
        cwd=repo_root,
        env=env,
    )
    _run(
        [*cli_cmd, "validate", "examples/guardrails/guardrail.py", "--type", "guardrail"],
        cwd=repo_root,
        env=env,
    )

    _assert_submission_entrypoints(repo_root)

    _run(
        [
            python_bin,
            "-m",
            "pytest",
            "-q",
            "tests/unit/test_evaluation_attack_contract.py",
            "tests/unit/test_scoring.py",
        ],
        cwd=repo_root,
        env=env,
    )

    with tempfile.TemporaryDirectory(prefix="aicomp_smoke_") as tmpdir:
        tmp_path = Path(tmpdir)
        submission_zip = tmp_path / "submission.zip"
        score_txt = tmp_path / "scores.txt"
        score_json = tmp_path / "scores.json"

        _build_submission_zip(repo_root, submission_zip)
        _run(
            [
                python_bin,
                "evaluation.py",
                "--submission_zip",
                str(submission_zip),
                "--seconds",
                str(float(args.seconds)),
                "--out",
                str(score_txt),
                "--out_json",
                str(score_json),
            ],
            cwd=repo_root,
            env=env,
            quiet=True,
        )

        _require_file(score_txt)
        _require_file(score_json)
        payload = _load_json(score_json)
        print("\nSmoke result summary:")
        print(
            json.dumps(
                {
                    "final_score": payload.get("final_score"),
                    "attack": payload.get("attack"),
                    "defense": payload.get("defense"),
                    "scoring_mode": payload.get("scoring_mode"),
                },
                indent=2,
            )
        )

    if args.extended:
        _run([python_bin, "scripts/evaluate_all_sample_attacks.py"], cwd=repo_root, env=env)
        _run([python_bin, "scripts/evaluate_all_guardrails.py"], cwd=repo_root, env=env)

    print("\nAll smoke checks completed successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
