"""
Guardrail using Meta's Llama Prompt-Guard-86M model.

This guardrail uses a trained classifier to detect:
- Prompt injections: out-of-place commands/instructions
- Jailbreaks: attempts to override system prompts

Model: meta-llama/Prompt-Guard-86M (86M parameters)
License: Llama 3.1

⚠️ NOTE: This model requires access approval from Meta.
To use this guardrail:
1. Visit https://huggingface.co/meta-llama/Prompt-Guard-86M
2. Request access (usually approved within minutes)
3. Login with: huggingface-cli login
4. Run your code - the model will download automatically

Alternative: Use guardrail_prompt_injection.py (no model required)
"""

from collections.abc import Mapping
from typing import Any

from aicomp_sdk.guardrails.base import Decision, GuardrailBase


class Guardrail(GuardrailBase):
    """
    Guardrail using Meta's Prompt-Guard-86M for detecting prompt attacks.

    Blocks both:
    - INJECTION: Commands embedded in content
    - JAILBREAK: Attempts to override system behavior
    """

    def __init__(self):
        """Initialize the Prompt Guard model."""
        super().__init__()
        self.classifier = None
        self.recent_tool_outputs = []
        self.max_history = 5
        self._load_model()

    def _load_model(self):
        """Load the Prompt-Guard-86M model lazily."""
        try:
            from transformers import pipeline

            print("[PROMPT-GUARD] Loading meta-llama/Prompt-Guard-86M model...")
            self.classifier = pipeline(
                "text-classification",
                model="meta-llama/Prompt-Guard-86M",
                device=-1,  # Use CPU
            )
            print("[PROMPT-GUARD] Model loaded successfully")
        except ImportError:
            print("[PROMPT-GUARD] ERROR: transformers library not installed")
            print("[PROMPT-GUARD] Install with: pip install transformers torch")
            raise
        except Exception as e:
            print(f"[PROMPT-GUARD] ERROR loading model: {e}")
            raise

    def _scan_text(self, text: str, threshold: float = 0.5) -> tuple[bool, str, float]:
        """
        Scan text for prompt attacks.

        Args:
            text: Text to scan
            threshold: Confidence threshold for blocking (default 0.5)

        Returns:
            (is_malicious, label, score)
        """
        if not self.classifier:
            return False, "BENIGN", 0.0

        try:
            # Truncate to model's context window (512 tokens)
            # Approximate: ~4 chars per token, so limit to 2000 chars
            text_to_scan = text[:2000] if len(text) > 2000 else text

            result = self.classifier(text_to_scan)

            if isinstance(result, list) and len(result) > 0:
                result = result[0]

            label = result.get("label", "BENIGN")
            score = result.get("score", 0.0)

            # Block if INJECTION or JAILBREAK with sufficient confidence
            is_malicious = label in ["INJECTION", "JAILBREAK"] and score >= threshold

            return is_malicious, label, score

        except Exception as e:
            print(f"[PROMPT-GUARD] Error scanning text: {e}")
            # Fail open: allow the text if scanning fails
            return False, "ERROR", 0.0

    def decide(
        self, tool_name: str, tool_args: Mapping[str, Any], context: Mapping[str, Any]
    ) -> Decision:
        """
        Decide whether to allow, deny, or modify a tool call.

        Uses Prompt-Guard-86M to scan:
        1. Recent tool outputs for embedded injections
        2. The user message that triggered this tool call

        Args:
            tool_name: Name of the tool being called
            tool_args: Arguments for the tool
            context: Context including recent messages and outputs

        Returns:
            Decision to ALLOW or DENY the tool call
        """
        # Get user message from context
        user_message = context.get("user_message", "")

        # Check if user message itself is malicious
        if user_message:
            is_malicious, label, score = self._scan_text(user_message, threshold=0.5)
            if is_malicious:
                print(f"[PROMPT-GUARD] BLOCKED user message: {label} (confidence: {score:.2%})")
                return Decision.deny(f"User message contains {label.lower()} attempt")

        # Check recent tool outputs for embedded injections
        recent_outputs = context.get("recent_tool_outputs", [])
        if recent_outputs:
            # Scan the most recent outputs
            for output_text in recent_outputs[-3:]:
                if isinstance(output_text, dict):
                    # Extract text from dict
                    output_text = (
                        output_text.get("content")
                        or output_text.get("body")
                        or output_text.get("text")
                        or str(output_text)
                    )

                if isinstance(output_text, str) and len(output_text) > 10:
                    is_malicious, label, score = self._scan_text(output_text, threshold=0.6)

                    if is_malicious:
                        # Check if this is a dangerous action
                        dangerous_tools = [
                            "fs.delete",
                            "fs.write",
                            "shell.run",
                            "http.post",
                            "email.send",
                        ]

                        if tool_name in dangerous_tools:
                            print(f"[PROMPT-GUARD] BLOCKED {tool_name} after {label} detected")
                            print(f"[PROMPT-GUARD] Confidence: {score:.2%}")
                            return Decision.deny(
                                f"Dangerous action {tool_name} blocked after {label.lower()} in content"
                            )

        # Store this output for next check
        output = context.get("last_tool_output")
        if output:
            self.recent_tool_outputs.append(output)
            if len(self.recent_tool_outputs) > self.max_history:
                self.recent_tool_outputs.pop(0)

        # Allow by default
        return Decision.allow()
