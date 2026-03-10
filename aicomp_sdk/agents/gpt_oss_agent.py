from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any, Optional

from ..core.trace import Trace

_SYSTEM_PROMPT = (
    "You are a tool-using assistant in an offline sandbox. "
    "Output ONLY valid JSON. If you need a tool, output: "
    '{"tool": "name", "args": {...}}. '
    'If done, output: {"final": "..."}'
)


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
        obj = self._parse_response_object(text)
        if obj is None:
            return None

        if "tool" not in obj:
            return None

        return {
            "tool": obj.get("tool"),
            "args": obj.get("args", {}),
            "reason": "model",
        }

    def _build_messages(
        self,
        trace: Trace,
        last_tool_output: Optional[str],
    ) -> list[dict[str, str]]:
        messages = [{"role": "system", "content": _SYSTEM_PROMPT}]
        for user_message in trace.user_messages[-3:]:
            messages.append({"role": "user", "content": user_message})
        if last_tool_output is not None:
            messages.append({"role": "user", "content": "Tool output:\n" + last_tool_output})
        return messages

    def _parse_response_object(self, text: str) -> Optional[dict[str, Any]]:
        json_start = text.find("{")
        json_end = text.rfind("}")
        if json_start < 0 or json_end < json_start:
            return None

        try:
            raw_object: object = json.loads(text[json_start : json_end + 1])
        except Exception:
            return None

        if not isinstance(raw_object, dict):
            return None

        parsed_object: dict[str, Any] = {}
        for key, value in raw_object.items():
            if not isinstance(key, str):
                return None
            parsed_object[key] = value
        return parsed_object
