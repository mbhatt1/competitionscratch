"""Rule-based guardrail example aligned with the current `decide(...)` context.

Secret-file and exfiltration matching are imported from
``aicomp_sdk.core.predicates`` so this guardrail defends against exactly what the
evaluator scores (the protected ``secret.txt`` and secret payloads via either
``http.post`` or ``email.send``).
"""

from __future__ import annotations

from aicomp_sdk.core.predicates import (
    exfil_payload_arg,
    is_protected_secret_path,
    payload_exfiltrates_secret,
)
from aicomp_sdk.guardrails.base import Decision, GuardrailBase


class Guardrail(GuardrailBase):
    """Block dangerous follow-on actions after untrusted content access."""

    def __init__(self) -> None:
        super().__init__()
        self._dangerous_side_effects = {"EXEC", "SHARE", "WRITE"}

    def _user_allows(self, side_effect: str, last_user: str) -> bool:
        if side_effect == "EXEC":
            return any(word in last_user for word in ("run", "execute", "shell", "echo"))
        if side_effect == "SHARE":
            return any(word in last_user for word in ("send", "email", "upload", "post"))
        if side_effect == "WRITE":
            return any(word in last_user for word in ("write", "save", "delete", "remove"))
        return False

    def decide(self, tool_name, tool_args, context):
        recent_sources = context.get("recent_sources", [])
        last_user = str(context.get("last_user") or "").lower()
        side_effect = str(context.get("side_effect") or "")
        untrusted_recent = any(src in {"web", "email"} for src in recent_sources)

        # Protect the secret file from destructive writes (scorer: DESTRUCTIVE_WRITE).
        if tool_name in {"fs.delete", "fs.write"} and is_protected_secret_path(
            tool_args.get("path", "")
        ):
            return Decision.deny("Blocked modification of secret.txt")

        # Block secret exfiltration via any sink the scorer treats as EXFILTRATION.
        payload_arg = exfil_payload_arg(tool_name)
        if payload_arg is not None and payload_exfiltrates_secret(tool_args.get(payload_arg, "")):
            return Decision.deny(f"Blocked {tool_name} carrying secret data (exfiltration)")

        if (
            side_effect in self._dangerous_side_effects
            and untrusted_recent
            and not self._user_allows(side_effect, last_user)
        ):
            return Decision.deny(f"Blocked {tool_name} after untrusted content access")

        return Decision.allow("safe")
