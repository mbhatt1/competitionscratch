from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any, Self

from ..types import HFBackendConfig, HFGenerationRequest, HFGenerationResponse


def _resolve_hf_optional_override(
    explicit_value: str | None,
    *,
    env_var: str,
) -> str | None:
    if explicit_value is not None:
        stripped_value = explicit_value.strip()
        return stripped_value or None

    env_value = os.environ.get(env_var, "").strip()
    return env_value or None


def _build_hf_backend_config(
    *,
    default_model_id: str,
    model_id_env_var: str,
    model_path_env_var: str,
    model_path: str | None = None,
    model_id: str | None = None,
    local_files_only: bool = True,
    device_map: str = "auto",
    torch_dtype: str = "auto",
    tokenizer_kwargs: Mapping[str, Any] | None = None,
    model_kwargs: Mapping[str, Any] | None = None,
    trust_remote_code: bool | None = None,
    attn_implementation: str | None = None,
    max_new_tokens: int = 256,
    generation_kwargs: Mapping[str, Any] | None = None,
) -> HFBackendConfig:
    resolved_generation_kwargs = (
        dict(generation_kwargs) if generation_kwargs is not None else {"do_sample": False}
    )
    resolved_model_id = (
        _resolve_hf_optional_override(model_id, env_var=model_id_env_var) or default_model_id
    )
    resolved_model_path = _resolve_hf_optional_override(
        model_path,
        env_var=model_path_env_var,
    )
    return HFBackendConfig(
        model_id=resolved_model_id,
        model_path=resolved_model_path,
        local_files_only=local_files_only,
        device_map=device_map,
        torch_dtype=torch_dtype,
        tokenizer_kwargs=dict(tokenizer_kwargs or {}),
        model_kwargs=dict(model_kwargs or {}),
        trust_remote_code=trust_remote_code,
        attn_implementation=attn_implementation,
        max_new_tokens=max_new_tokens,
        generation_kwargs=resolved_generation_kwargs,
    )


class HFChatTemplateBackend:
    def __init__(
        self,
        *,
        tokenizer: Any,
        model: Any,
        config: HFBackendConfig,
    ) -> None:
        self.tokenizer = tokenizer
        self.model = model
        self.config = config

    @classmethod
    def from_pretrained(cls, config: HFBackendConfig) -> Self:
        try:
            from transformers import AutoModelForCausalLM, AutoTokenizer
        except Exception as err:
            exc = RuntimeError("Transformers SDK is not available")
            exc.add_note(
                "Install the 'transformers' dependency before using local HF chat-template agents."
            )
            raise exc from err

        source = config.model_source()
        try:
            tokenizer = AutoTokenizer.from_pretrained(
                source,
                **config.tokenizer_loader_kwargs(),
            )
            model = AutoModelForCausalLM.from_pretrained(
                source,
                **config.model_loader_kwargs(),
            )
        except Exception as err:
            exc = RuntimeError(f"Failed to load HF chat-template backend from '{source}'")
            exc.add_note(f"Model source: {source}")
            raise exc from err

        return cls(tokenizer=tokenizer, model=model, config=config)

    def generate(self, request: HFGenerationRequest) -> HFGenerationResponse:
        if request.add_generation_prompt and request.continue_final_message:
            raise ValueError(
                "HF generation request cannot set both add_generation_prompt and "
                "continue_final_message"
            )

        template_kwargs: dict[str, Any] = {
            "tools": list(request.tools),
            "add_generation_prompt": request.add_generation_prompt,
            "continue_final_message": request.continue_final_message,
            "return_dict": True,
            "return_tensors": "pt",
        }
        if request.chat_template is not None:
            template_kwargs["chat_template"] = request.chat_template

        inputs = self.tokenizer.apply_chat_template(
            list(request.messages),
            **template_kwargs,
        ).to(self.model.device)
        generate_kwargs = dict(request.generation_kwargs)
        generate_kwargs["max_new_tokens"] = request.max_new_tokens
        generated = self.model.generate(**inputs, **generate_kwargs)

        prompt_tokens = inputs["input_ids"].shape[-1]
        generated_tokens = generated[0][prompt_tokens:]
        raw_text = self._decode_generated_tokens(
            generated_tokens,
            skip_special_tokens=False,
        )
        cleaned_text = self._decode_generated_tokens(
            generated_tokens,
            skip_special_tokens=True,
        )
        return HFGenerationResponse(text=cleaned_text.strip(), raw_text=raw_text)

    def _decode_generated_tokens(
        self,
        generated_tokens: Any,
        *,
        skip_special_tokens: bool,
    ) -> str:
        return str(
            self.tokenizer.decode(
                generated_tokens,
                skip_special_tokens=skip_special_tokens,
                clean_up_tokenization_spaces=False,
            )
        )
