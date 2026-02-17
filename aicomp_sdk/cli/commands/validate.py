"""
Validate command - fast validation of submission files.

Checks:
- File exists and is valid Python
- Has required class/function (Attacker or Guardrail)
- Imports are valid
- Basic syntax check
- Returns detailed error messages
"""

import ast
from pathlib import Path


def validate_python_syntax(filepath: Path) -> tuple[bool, str]:
    """Check if file has valid Python syntax."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            code = f.read()
        ast.parse(code)
        return True, "Valid Python syntax"
    except SyntaxError as e:
        return False, f"Syntax error at line {e.lineno}: {e.msg}"
    except Exception as e:
        return False, f"Error parsing file: {e}"


def validate_imports(filepath: Path) -> tuple[bool, list[str]]:
    """Check if imports are valid and can be resolved."""
    issues = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            code = f.read()

        tree = ast.parse(code)

        # Extract all imports
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    # Skip relative imports and standard library
                    if alias.name.startswith("aicomp_sdk"):
                        # Check if it's a valid aicomp_sdk import
                        parts = alias.name.split(".")
                        if len(parts) > 1:
                            # Check common valid imports
                            valid_imports = [
                                "aicomp_sdk.core.env",
                                "aicomp_sdk.guardrails.hooks",
                                "aicomp_sdk.guardrails.hooks_simple",
                                "aicomp_sdk.guardrails.base",
                                "aicomp_sdk.scoring",
                                "aicomp_sdk.core.predicates",
                            ]
                            if alias.name not in valid_imports and not any(
                                alias.name.startswith(v) for v in valid_imports
                            ):
                                issues.append(
                                    f"Unusual import: {alias.name} (may not be available)"
                                )

            elif isinstance(node, ast.ImportFrom):
                if node.module and node.module.startswith("aicomp_sdk"):
                    # Validate common imports
                    valid_from = {
                        "aicomp_sdk": ["GuardrailBase", "Decision"],
                        "aicomp_sdk.core.env": ["SandboxEnv"],
                        "aicomp_sdk.guardrails.base": ["GuardrailBase", "Decision"],
                        "aicomp_sdk.guardrails.hooks_simple": [
                            "attack_hook",
                            "defense_hook",
                            "clear_hooks",
                        ],
                        "aicomp_sdk.scoring": ["score_attack", "score_defense"],
                    }

                    if node.module in valid_from:
                        for alias in node.names:
                            if alias.name not in valid_from[node.module] and alias.name != "*":
                                issues.append(f"Unknown import: {alias.name} from {node.module}")

        return len(issues) == 0, issues

    except Exception as e:
        return False, [f"Error analyzing imports: {e}"]


def validate_attack_structure(filepath: Path) -> tuple[bool, list[str]]:
    """Validate attack submission structure."""
    issues = []

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            code = f.read()

        tree = ast.parse(code)

        # Check for AttackAlgorithm class
        has_attack_class = False
        has_run_method = False

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                if node.name == "AttackAlgorithm":
                    has_attack_class = True

                    # Check for run method
                    for item in node.body:
                        if isinstance(item, ast.FunctionDef) and item.name == "run":
                            has_run_method = True

                            # Check run method signature
                            args = item.args
                            arg_names = [arg.arg for arg in args.args]

                            if "self" not in arg_names:
                                issues.append(
                                    "run() method should be an instance method (missing self)"
                                )
                            if "env" not in arg_names:
                                issues.append("run() method missing required 'env' parameter")
                            if "budget" not in arg_names:
                                issues.append("run() method missing required 'budget' parameter")

        if not has_attack_class:
            issues.append("Missing 'AttackAlgorithm' class")
        if not has_run_method:
            issues.append("AttackAlgorithm class missing 'run' method")

        return len(issues) == 0, issues

    except Exception as e:
        return False, [f"Error analyzing structure: {e}"]


def validate_guardrail_structure(filepath: Path) -> tuple[bool, list[str]]:
    """Validate guardrail submission structure."""
    issues = []

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            code = f.read()

        tree = ast.parse(code)

        # Check for Guardrail class
        has_guardrail_class = False
        has_decide_method = False

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                if node.name == "Guardrail":
                    has_guardrail_class = True

                    # Check for decide method
                    for item in node.body:
                        if isinstance(item, ast.FunctionDef) and item.name == "decide":
                            has_decide_method = True

                            # Check decide method signature
                            args = item.args
                            arg_names = [arg.arg for arg in args.args]

                            if "self" not in arg_names:
                                issues.append(
                                    "decide() method should be an instance method (missing self)"
                                )
                            if "tool_name" not in arg_names:
                                issues.append(
                                    "decide() method missing required 'tool_name' parameter"
                                )
                            if "tool_args" not in arg_names:
                                issues.append(
                                    "decide() method missing required 'tool_args' parameter"
                                )
                            if "context" not in arg_names:
                                issues.append(
                                    "decide() method missing required 'context' parameter"
                                )

        if not has_guardrail_class:
            issues.append("Missing 'Guardrail' class")
        if not has_decide_method:
            issues.append("Guardrail class missing 'decide' method")

        return len(issues) == 0, issues

    except Exception as e:
        return False, [f"Error analyzing structure: {e}"]


def auto_detect_type(filepath: Path) -> str:
    """Auto-detect submission type from filename or content."""
    filename = filepath.name.lower()

    if "attack" in filename:
        return "attack"
    elif "guardrail" in filename or "guard" in filename:
        return "guardrail"

    # Check content
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        if "class AttackAlgorithm" in content:
            return "attack"
        elif "class Guardrail" in content:
            return "guardrail"
    except Exception:
        pass

    return "unknown"


def run_validate(args) -> int:
    """Execute validate command."""
    from aicomp_sdk.cli.main import (
        print_error,
        print_info,
        print_success,
        print_warning,
    )

    filepath = Path(args.file)

    # Check file exists
    if not filepath.exists():
        print_error(f"File not found: {filepath}")
        return 1

    print_info(f"Validating: {filepath}")

    # Detect type
    submission_type = args.type
    if submission_type == "auto":
        submission_type = auto_detect_type(filepath)
        if submission_type == "unknown":
            print_warning("Could not auto-detect submission type. Specify with --type")
            return 1
        print_info(f"Detected type: {submission_type}")

    # Run validations
    all_valid = True

    # 1. Syntax check
    print_info("Checking Python syntax...")
    syntax_valid, syntax_msg = validate_python_syntax(filepath)
    if syntax_valid:
        print_success(syntax_msg)
    else:
        print_error(syntax_msg)
        all_valid = False
        return 1  # Can't continue if syntax is invalid

    # 2. Import check
    print_info("Checking imports...")
    imports_valid, import_issues = validate_imports(filepath)
    if imports_valid:
        print_success("All imports look valid")
    else:
        for issue in import_issues:
            print_warning(issue)

    # 3. Structure check
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

    # Summary
    print()
    if all_valid:
        print_success(f"✅ Validation passed! {filepath} is ready to test.")
        return 0
    else:
        print_error("❌ Validation failed. Please fix the issues above.")
        return 1
