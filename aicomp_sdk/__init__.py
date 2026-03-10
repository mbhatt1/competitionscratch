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
from .core.env import SandboxEnv
from .core.env_api import AttackEnvProtocol, EnvSelection, parse_env_selection

try:
    from .core.gym_env import GymAttackEnv as _GymAttackEnv
except ImportError:
    GymAttackEnv: Any = None
else:
    GymAttackEnv = _GymAttackEnv

from .guardrails.base import Decision, GuardrailBase

# Advanced hooks API (for power users)
from .guardrails.hooks import (
    HookCallback,
    HookContext,
    HookRegistry,
    HookResult,
    HookStage,
    create_detection_hook,
    create_lpci_cross_session_hook,
    create_lpci_tool_poisoning_hook,
    create_lpci_vector_store_hook,
    create_memory_hook,
    create_payload_injection_hook,
    create_trigger_hook,
    get_hook_registry,
)

# Simple hooks API (recommended for most users)
from .guardrails.hooks_simple import (
    attack_hook,
    clear_hooks,
    defense_hook,
    poison_tool,
    store_payload,
)

__all__ = [
    # Core SDK
    "SandboxEnv",
    "GymAttackEnv",
    "AttackEnvProtocol",
    "EnvSelection",
    "parse_env_selection",
    "GuardrailBase",
    "Decision",
    "AttackAlgorithmBase",
    "AttackCandidate",
    "AttackRunConfig",
    # Simple Hooks API (recommended)
    "attack_hook",
    "defense_hook",
    "clear_hooks",
    "store_payload",
    "poison_tool",
    # Advanced Hooks API
    "HookRegistry",
    "HookStage",
    "HookContext",
    "HookResult",
    "HookCallback",
    "get_hook_registry",
    "create_payload_injection_hook",
    "create_trigger_hook",
    "create_detection_hook",
    "create_memory_hook",
    "create_lpci_vector_store_hook",
    "create_lpci_tool_poisoning_hook",
    "create_lpci_cross_session_hook",
]
