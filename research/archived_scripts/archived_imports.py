"""
Import compatibility helper for archived research scripts.

This module provides backward-compatible imports for scripts that
originally imported from the now-defunct examples_hooks_submission/ directory.

Usage:
    from archived_imports import setup_imports
    setup_imports()  # Configure paths
    
    # Then use updated imports
    from examples.guardrails.guardrail_prompt_injection import Guardrail
"""

import sys
from pathlib import Path


def setup_imports():
    """Configure sys.path for archived scripts to access SDK and examples."""
    # Get repository root (three levels up from this file: archived_scripts -> research -> repo_root)
    repo_root = Path(__file__).resolve().parent.parent.parent
    
    # Add paths in order of priority
    # Only add repo_root - this allows importing:
    # - aicomp_sdk (package in repo_root)
    # - examples.guardrails (examples/ is a package in repo_root)
    # - tests.integration (tests/ is a package in repo_root)
    paths_to_add = [
        str(repo_root),
    ]
    
    for path in paths_to_add:
        if path not in sys.path:
            sys.path.insert(0, path)
    
    return repo_root


def get_fixtures_dir():
    """Get the fixtures directory path."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    return repo_root / "fixtures"


# Convenience re-exports for backward compatibility
def import_guardrails():
    """Import and return common guardrail classes."""
    from examples.guardrails.guardrail_prompt_injection import Guardrail as PromptInjectionGuardrail
    from examples.guardrails.guardrail_simple import Guardrail as SimpleGuardrail
    
    return {
        'PromptInjectionGuardrail': PromptInjectionGuardrail,
        'SimpleGuardrail': SimpleGuardrail,
    }


def import_attacks():
    """Import and return common attack classes."""
    from examples.attacks.attack_working import AttackAlgorithm as WorkingAttack
    
    return {
        'WorkingAttack': WorkingAttack,
    }


def import_test_utils():
    """Import and return test utilities."""
    from tests.integration.test_verify_findings import detect_real_attacks
    
    return {
        'detect_real_attacks': detect_real_attacks,
    }
