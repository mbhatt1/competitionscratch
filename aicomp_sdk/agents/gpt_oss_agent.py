from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Optional

from ..core.trace import Trace
from .tool_call_protocol import build_agent_messages, parse_tool_action


class GPTOSSBackend:
    def __init__(self, model_path: str) -> None:
        self.model_path = model_path
        self._ready = False
        self._tokenizer = None
        self._model = None
        self._load()

    def _load(self) -> None:
        try:
            from transformers import AutoModelForCausalLM, AutoTokenizer
        except Exception:
            return
        try:
            self._tokenizer = AutoTokenizer.from_pretrained(self.model_path)
            self._model = AutoModelForCausalLM.from_pretrained(
                self.model_path,
                torch_dtype="auto",
                device_map="auto",
            )
            self._ready = True
        except Exception:
            self._ready = False

    def ready(self) -> bool:
        return self._ready

    def generate(
        self,
        messages: Sequence[Mapping[str, str]],
        max_new_tokens: int = 256,
    ) -> str:
        if self._tokenizer is None or self._model is None:
            raise RuntimeError(
                "GPTOSSBackend is not initialized. Ensure GPT_OSS_MODEL_PATH points to a "
                "valid local model and that Transformers/Torch are installed."
            )

        tokenizer = self._tokenizer
        model = self._model

        chat_messages = [dict(message) for message in messages]
        inputs = tokenizer.apply_chat_template(
            chat_messages,
            add_generation_prompt=True,
            return_tensors="pt",
            return_dict=True,
        ).to(model.device)
        out = model.generate(**inputs, max_new_tokens=max_new_tokens, do_sample=False)
        text = tokenizer.decode(out[0][inputs["input_ids"].shape[-1] :], skip_special_tokens=True)
        return text


class GPTOSSAgent:
    """Tool-using agent powered by gpt-oss-20b (optional)."""

    def __init__(self, backend: GPTOSSBackend) -> None:
        self.backend = backend

    def next_tool_call(
        self, trace: Trace, last_tool_output: Optional[str]
    ) -> Optional[dict[str, Any]]:
        messages = self._build_messages(trace, last_tool_output)

        text = self.backend.generate(messages, max_new_tokens=256).strip()
        action = self._parse_response_object(text)
        if action is None or action["done"]:
            return None

        return {
            "tool": action["tool"],
            "args": action["args"],
            "reason": "model",
        }

    def _build_messages(
        self,
        trace: Trace,
        last_tool_output: Optional[str],
    ) -> list[dict[str, str]]:
        return build_agent_messages(trace, last_tool_output)

    def _parse_response_object(self, text: str) -> Optional[dict[str, Any]]:
        return parse_tool_action(text)
