"""AI Competition SDK for red teaming tool-using AI agents.

This package provides a comprehensive framework for:
- Building and testing AI agent security
- Implementing attack algorithms
- Creating defensive guardrails
- Running security competitions
"""

from typing import Any

# Core SDK
from .attacks import (
    AttackAlgorithmBase,
    AttackCandidate,
    AttackRunConfig,
)
from .core.env.api import (
    AttackEnvProtocol,
    DiagnosticsEnv,
    EnvInteractionResult,
    EnvRunDiagnostics,
    EnvSelection,
    coerce_env_selection,
)
from .core.env.sandbox import SandboxEnv

try:
    from .core.env.gym import GymAttackEnv as _GymAttackEnv
except ImportError:
    GymAttackEnv: Any = None
else:
    GymAttackEnv = _GymAttackEnv

from .guardrails.base import Decision, DecisionAction, GuardrailBase

__all__ = [
    # Core SDK
    "SandboxEnv",
    "GymAttackEnv",
    "AttackEnvProtocol",
    "coerce_env_selection",
    "DiagnosticsEnv",
    "EnvRunDiagnostics",
    "EnvInteractionResult",
    "EnvSelection",
    "GuardrailBase",
    "Decision",
    "DecisionAction",
    "AttackAlgorithmBase",
    "AttackCandidate",
    "AttackRunConfig",
]
