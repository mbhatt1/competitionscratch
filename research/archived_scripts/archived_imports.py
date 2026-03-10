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

import os
import sys
from pathlib import Path


def get_repo_root() -> Path:
    """Get the repository root path."""
    return Path(__file__).resolve().parent.parent.parent


def setup_imports() -> Path:
    """Configure sys.path for archived scripts to access SDK and examples."""
    repo_root = get_repo_root()

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


def get_fixtures_dir() -> Path:
    """Get the fixtures directory path."""
    return get_repo_root() / "fixtures"


def require_openai_key() -> str:
    """Require an OpenAI API key for archived OpenAI-backed experiments."""
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY required for this archived experiment.")
    return api_key


def build_archived_agent(selection: str):
    """Build an explicit agent for archived SandboxEnv-based experiments."""
    from aicomp_sdk.agents import build_agent

    if selection == "openai":
        require_openai_key()
    elif selection != "deterministic":
        raise ValueError(f"Unsupported archived agent selection: {selection}")

    return build_agent(selection)


def create_archived_sandbox_env(
    *,
    seed: int,
    fixtures_dir: Path,
    guardrail,
    agent_selection: str,
):
    """Create a SandboxEnv using the current explicit-agent API."""
    from aicomp_sdk.core.env import SandboxEnv

    return SandboxEnv(
        seed=seed,
        fixtures_dir=fixtures_dir,
        agent=build_archived_agent(agent_selection),
        guardrail=guardrail,
    )


# Convenience re-exports for backward compatibility
def import_guardrails():
    """Import and return common guardrail classes."""
    from examples.guardrails.guardrail_prompt_injection import Guardrail as PromptInjectionGuardrail
    from examples.guardrails.guardrail_simple import Guardrail as SimpleGuardrail

    return {
        "PromptInjectionGuardrail": PromptInjectionGuardrail,
        "SimpleGuardrail": SimpleGuardrail,
    }


def import_attacks():
    """Import and return common attack classes.

    Note: ``WorkingAttack`` follows the modern ``AttackRunConfig`` /
    ``AttackCandidate`` contract rather than the older dict-based attack API.
    """
    from examples.attacks.attack_working import AttackAlgorithm as WorkingAttack

    return {
        "WorkingAttack": WorkingAttack,
    }


def import_test_utils():
    """Import and return test utilities."""
    from tests.integration.test_verify_findings import detect_real_attacks

    return {
        "detect_real_attacks": detect_real_attacks,
    }
