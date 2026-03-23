"""
Validate command - fast validation of submission files.

Checks:
- File exists and is valid Python
- Has required class/function (`AttackAlgorithm` or `Guardrail`)
- Imports are valid
- Returns detailed error messages
"""

import ast
import importlib
import importlib.util
import zipfile
from contextlib import ExitStack
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Literal

from aicomp_sdk.evaluation.tracks import EvaluationTrack

SubmissionType = Literal["attack", "guardrail"]


def _parse_python_file(filepath: Path) -> ast.AST:
    return ast.parse(filepath.read_text(encoding="utf-8"))


def _class_base_names(node: ast.ClassDef) -> set[str]:
    names: set[str] = set()
    for base in node.bases:
        if isinstance(base, ast.Name):
            names.add(base.id)
        elif isinstance(base, ast.Attribute):
            names.add(base.attr)
    return names


def _resolve_sdk_imported_name(
    module_name: str,
    imported_name: str,
    module_cache: dict[str, object],
) -> bool:
    if imported_name == "*":
        return True

    module = module_cache.get(module_name)
    if module is None:
        try:
            module = importlib.import_module(module_name)
        except Exception:
            return False
        module_cache[module_name] = module

    if hasattr(module, imported_name):
        return True

    try:
        return importlib.util.find_spec(f"{module_name}.{imported_name}") is not None
    except ModuleNotFoundError:
        return False


def validate_python_syntax(filepath: Path) -> tuple[bool, str]:
    """Check if file has valid Python syntax."""
    try:
        _parse_python_file(filepath)
        return True, "Valid Python syntax"
    except SyntaxError as e:
        return False, f"Syntax error at line {e.lineno}: {e.msg}"
    except Exception as e:
        return False, f"Error parsing file: {e}"


def validate_imports(filepath: Path) -> tuple[bool, list[str]]:
    """Check if imports are valid and can be resolved."""
    issues: list[str] = []
    module_cache: dict[str, object] = {}
    try:
        tree = _parse_python_file(filepath)

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if not alias.name.startswith("aicomp_sdk"):
                        continue
                    if importlib.util.find_spec(alias.name) is None:
                        issues.append(f"Could not resolve import: {alias.name}")

            if not isinstance(node, ast.ImportFrom):
                continue
            if node.module is None or not node.module.startswith("aicomp_sdk"):
                continue
            if importlib.util.find_spec(node.module) is None:
                issues.append(f"Could not resolve import: {node.module}")
                continue
            for alias in node.names:
                if not _resolve_sdk_imported_name(node.module, alias.name, module_cache):
                    issues.append(f"Could not resolve import: {alias.name} from {node.module}")

        return len(issues) == 0, issues

    except Exception as e:
        return False, [f"Error analyzing imports: {e}"]


def validate_attack_structure(filepath: Path) -> tuple[bool, list[str]]:
    """Validate attack submission structure."""
    issues: list[str] = []

    try:
        tree = _parse_python_file(filepath)

        has_attack_class = False
        has_run_method = False

        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef) or node.name != "AttackAlgorithm":
                continue

            has_attack_class = True
            base_names = _class_base_names(node)
            if "AttackAlgorithmBase" not in base_names:
                issues.append("AttackAlgorithm must inherit from AttackAlgorithmBase")

            for item in node.body:
                if not isinstance(item, ast.FunctionDef) or item.name != "run":
                    continue

                has_run_method = True

                arg_names = [arg.arg for arg in item.args.args]
                if "self" not in arg_names:
                    issues.append("run() method should be an instance method (missing self)")
                if "env" not in arg_names:
                    issues.append("run() method missing required 'env' parameter")
                if "config" not in arg_names:
                    issues.append("run() method missing required 'config' parameter")

        if not has_attack_class:
            issues.append("Missing 'AttackAlgorithm' class")
        if not has_run_method:
            issues.append("AttackAlgorithm class missing 'run' method")

        return len(issues) == 0, issues

    except Exception as e:
        return False, [f"Error analyzing structure: {e}"]


def validate_guardrail_structure(filepath: Path) -> tuple[bool, list[str]]:
    """Validate guardrail submission structure."""
    issues: list[str] = []

    try:
        tree = _parse_python_file(filepath)

        has_guardrail_class = False
        has_decide_method = False

        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef) or node.name != "Guardrail":
                continue

            has_guardrail_class = True

            for item in node.body:
                if not isinstance(item, ast.FunctionDef) or item.name != "decide":
                    continue

                has_decide_method = True

                arg_names = [arg.arg for arg in item.args.args]
                if "self" not in arg_names:
                    issues.append("decide() method should be an instance method (missing self)")
                if "tool_name" not in arg_names:
                    issues.append("decide() method missing required 'tool_name' parameter")
                if "tool_args" not in arg_names:
                    issues.append("decide() method missing required 'tool_args' parameter")
                if "context" not in arg_names:
                    issues.append("decide() method missing required 'context' parameter")

        if not has_guardrail_class:
            issues.append("Missing 'Guardrail' class")
        if not has_decide_method:
            issues.append("Guardrail class missing 'decide' method")

        return len(issues) == 0, issues

    except Exception as e:
        return False, [f"Error analyzing structure: {e}"]


def _validate_single_file(filepath: Path, submission_type: SubmissionType) -> int:
    from aicomp_sdk.cli.main import (
        print_error,
        print_info,
        print_success,
    )

    all_valid = True

    print_info("Checking Python syntax...")
    syntax_valid, syntax_msg = validate_python_syntax(filepath)
    if syntax_valid:
        print_success(syntax_msg)
    else:
        print_error(syntax_msg)
        all_valid = False
        return 1
    print_info("Checking imports...")
    imports_valid, import_issues = validate_imports(filepath)
    if imports_valid:
        print_success("All imports look valid")
    else:
        for issue in import_issues:
            print_error(issue)
        all_valid = False

    print_info(f"Checking {submission_type} structure...")
    if submission_type == "attack":
        struct_valid, struct_issues = validate_attack_structure(filepath)
    else:
        struct_valid, struct_issues = validate_guardrail_structure(filepath)

    if struct_valid:
        print_success(f"Valid {submission_type} structure")
    else:
        for issue in struct_issues:
            print_error(issue)
        all_valid = False

    print()
    if all_valid:
        print_success(f"✅ Validation passed! {filepath} is ready to test.")
        if submission_type == "attack":
            print_info("Attack submissions are Kaggle-compatible when provided as attack.py.")
        return 0
    else:
        print_error("❌ Validation failed. Please fix the issues above.")
        return 1


def _extract_zip_member(
    stack: ExitStack,
    zip_path: Path,
    member_name: str,
) -> Path:
    tmp_dir = stack.enter_context(TemporaryDirectory())
    with zipfile.ZipFile(zip_path) as archive:
        try:
            archive.extract(member_name, path=tmp_dir)
        except KeyError as err:
            raise FileNotFoundError(f"Missing {member_name} in {zip_path.name}") from err
    return Path(tmp_dir) / member_name


def run_validate(args) -> int:
    """Execute validate command."""
    from aicomp_sdk.cli.main import print_error, print_info

    track = EvaluationTrack(args.track)
    filepath = Path(args.file)

    if not filepath.exists():
        print_error(f"File not found: {filepath}")
        return 1

    print_info(f"Validating: {filepath}")

    if track is EvaluationTrack.DUAL:
        if filepath.suffix != ".zip":
            print_error("Dual-track validation requires a submission zip.")
            return 1

        with ExitStack() as stack:
            try:
                attack_path = _extract_zip_member(stack, filepath, "attack.py")
                guardrail_path = _extract_zip_member(stack, filepath, "guardrail.py")
            except (FileNotFoundError, zipfile.BadZipFile) as err:
                print_error(str(err))
                return 1

            print_info("Validating redteam member: attack.py")
            attack_status = _validate_single_file(attack_path, "attack")
            print_info("Validating defense member: guardrail.py")
            guardrail_status = _validate_single_file(guardrail_path, "guardrail")
            return 0 if attack_status == 0 and guardrail_status == 0 else 1

    if filepath.suffix != ".py":
        print_error("Redteam and defense validation require a Python module.")
        return 1

    submission_type: SubmissionType = "attack" if track is EvaluationTrack.REDTEAM else "guardrail"
    return _validate_single_file(filepath, submission_type)
