"""Core SDK functionality."""

from typing import Any

from .cells import cell_signature
from .env.api import (
    AttackEnvProtocol,
    DiagnosticsEnv,
    EnvInteractionResult,
    EnvRunDiagnostics,
    EnvSelection,
    coerce_env_selection,
)
from .env.sandbox import SandboxEnv

try:
    from .env.gym import GymAttackEnv as _GymAttackEnv
except ImportError:
    GymAttackEnv: Any = None
else:
    GymAttackEnv = _GymAttackEnv
from .predicates import (
    eval_predicates,
    exfil_payload_arg,
    is_breach,
    is_protected_secret_path,
    payload_exfiltrates_secret,
)
from .tools import (
    RuntimeToolSpec,
    ToolContext,
    ToolDef,
    ToolHandler,
    ToolScope,
    ToolSideEffect,
    ToolSuite,
)
from .trace import ToolEvent, Trace

__all__ = [
    "AttackEnvProtocol",
    "DiagnosticsEnv",
    "EnvInteractionResult",
    "EnvRunDiagnostics",
    "EnvSelection",
    "GymAttackEnv",
    "SandboxEnv",
    "RuntimeToolSpec",
    "ToolContext",
    "ToolDef",
    "ToolEvent",
    "ToolHandler",
    "ToolScope",
    "ToolSideEffect",
    "ToolSuite",
    "Trace",
    "cell_signature",
    "coerce_env_selection",
    "eval_predicates",
    "exfil_payload_arg",
    "is_breach",
    "is_protected_secret_path",
    "payload_exfiltrates_secret",
]
