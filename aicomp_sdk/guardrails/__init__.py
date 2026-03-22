"""Guardrail system for defense strategies."""

from .base import Decision, DecisionAction, GuardrailBase
from .hooks import (
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
from .hooks_simple import (
    attack_hook,
    clear_hooks,
    defense_hook,
    poison_tool,
    store_payload,
)
from .optimal import Guardrail as OptimalGuardrail

__all__ = [
    "GuardrailBase",
    "Decision",
    "DecisionAction",
    "OptimalGuardrail",
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
