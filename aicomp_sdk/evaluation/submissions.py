"""Submission loading helpers for evaluator entrypoints."""

from __future__ import annotations

import importlib.util
import sys
import zipfile
from contextlib import ExitStack
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from types import ModuleType
from typing import Any, Final

from aicomp_sdk.evaluation.tracks import EvaluationTrack

MAX_SUBMISSION_FILE_BYTES: Final[int] = 5_000_000


def _canonical_member_name(raw_name: str) -> str:
    """Normalize zip member names and reject unsafe paths."""
    if not raw_name:
        raise ValueError("Empty zip member name")

    path = PurePosixPath(raw_name.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"Unsafe zip member path: {raw_name}")

    canonical = path.as_posix()
    if canonical in ("", "."):
        raise ValueError(f"Invalid zip member path: {raw_name}")
    return canonical


def _find_member(zf: zipfile.ZipFile, expected: str) -> zipfile.ZipInfo | None:
    """Find the expected member after canonicalizing names."""
    matches = []
    for info in zf.infolist():
        if _canonical_member_name(info.filename) == expected:
            matches.append(info)

    if not matches:
        return None
    if len(matches) > 1:
        raise ValueError(f"Duplicate archive entries for {expected}")

    info = matches[0]
    if info.is_dir():
        raise ValueError(f"Expected file, got directory: {info.filename}")
    return info


def load_module_from_file(
    filepath: Path,
    module_name: str,
    *,
    max_file_bytes: int = MAX_SUBMISSION_FILE_BYTES,
) -> ModuleType:
    """Load a Python module from a file after enforcing a size limit."""
    target = Path(filepath).resolve()
    if not target.exists():
        raise FileNotFoundError(target)
    if not target.is_file():
        raise ValueError(f"Expected file, got: {target}")
    if target.stat().st_size > max_file_bytes:
        raise ValueError(f"Submission file too large: {target.name}")

    if module_name in sys.modules:
        del sys.modules[module_name]

    spec = importlib.util.spec_from_file_location(module_name, str(target))
    if spec is None or spec.loader is None:
        exc = ImportError(f"Could not load module from {target}")
        exc.add_note(f"module_name={module_name}")
        raise exc

    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception as err:
        exc = ImportError(f"Failed to import module from {target}")
        exc.add_note(f"module_name={module_name}")
        exc.add_note(f"max_file_bytes={max_file_bytes}")
        raise exc from err
    return mod


def load_from_zip(
    zip_path: Path, module_name: str, file_name: str
) -> tuple[ModuleType | None, TemporaryDirectory]:
    """Safely extract a single expected file from a submission zip."""
    tmp = TemporaryDirectory(prefix="aicomp_sub_")
    tmp_path = Path(tmp.name)
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            info = _find_member(zf, file_name)
            if info is None:
                return None, tmp

            if info.file_size > MAX_SUBMISSION_FILE_BYTES:
                raise ValueError(f"Submission file too large: {info.filename}")

            source = zf.read(info)

        target = tmp_path / file_name
        target.write_bytes(source)
        mod = load_module_from_file(target, module_name)
        return mod, tmp
    except BaseException:
        tmp.cleanup()
        raise


def load_track_modules(
    stack: ExitStack,
    submission_path: Path,
    track: EvaluationTrack,
) -> tuple[type[Any] | None, type[Any] | None]:
    """Load submission classes for the selected track."""

    def load_zip_class(
        *,
        file_name: str,
        module_name: str,
        class_name: str,
    ) -> type[Any] | None:
        module, tmp_dir = load_from_zip(submission_path, module_name, file_name)
        stack.enter_context(tmp_dir)
        if module is None or not hasattr(module, class_name):
            return None
        class_obj = getattr(module, class_name)
        return class_obj if isinstance(class_obj, type) else None

    attack_cls = None
    guardrail_cls = None

    if submission_path.suffix == ".zip":
        if track in {EvaluationTrack.REDTEAM, EvaluationTrack.DUAL}:
            attack_cls = load_zip_class(
                file_name="attack.py",
                module_name="user_attack",
                class_name="AttackAlgorithm",
            )

        if track in {EvaluationTrack.DEFENSE, EvaluationTrack.DUAL}:
            guardrail_cls = load_zip_class(
                file_name="guardrail.py",
                module_name="user_guardrail",
                class_name="Guardrail",
            )

        return attack_cls, guardrail_cls

    if submission_path.suffix == ".py":
        if track is EvaluationTrack.REDTEAM:
            attack_mod = load_module_from_file(submission_path, "user_attack")
            attack_cls = (
                attack_mod.AttackAlgorithm if hasattr(attack_mod, "AttackAlgorithm") else None
            )
        elif track is EvaluationTrack.DEFENSE:
            guard_mod = load_module_from_file(submission_path, "user_guardrail")
            guardrail_cls = guard_mod.Guardrail if hasattr(guard_mod, "Guardrail") else None
        else:
            raise ValueError("Dual-track submissions must be provided as a zip archive.")
        return attack_cls, guardrail_cls

    raise ValueError(f"Unsupported file type: {submission_path.suffix}")
