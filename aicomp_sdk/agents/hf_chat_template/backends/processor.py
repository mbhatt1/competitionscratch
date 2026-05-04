from __future__ import annotations

from typing import Any, Self

from ..types import HFBackendConfig, HFGenerationRequest, HFGenerationResponse


class HFProcessorChatTemplateBackend:
    """Processor-backed HF chat-template backend for multimodal local models."""

    def __init__(
        self,
        *,
        processor: Any,
        model: Any,
        config: HFBackendConfig,
    ) -> None:
        self.processor = processor
        self.model = model
        self.config = config

    @classmethod
    def from_pretrained(cls, config: HFBackendConfig) -> Self:
        try:
            from transformers import AutoModelForMultimodalLM, AutoProcessor
        except Exception as err:
            exc = RuntimeError("Transformers SDK with Gemma 4 support is not available")
            exc.add_note(
                "Install a recent 'transformers' release before using local "
                "processor-backed HF chat-template agents."
            )
            raise exc from err

        source = config.model_source()
        try:
            processor = AutoProcessor.from_pretrained(
                source,
                **config.tokenizer_loader_kwargs(),
            )
            model = AutoModelForMultimodalLM.from_pretrained(
                source,
                **_model_loader_kwargs(config),
            )
        except Exception as err:
            exc = RuntimeError(f"Failed to load HF processor chat-template backend from '{source}'")
            exc.add_note(f"Model source: {source}")
            raise exc from err

        return cls(processor=processor, model=model, config=config)

    @property
    def tokenizer(self) -> Any:
        return getattr(self.processor, "tokenizer", None)

    def generate(self, request: HFGenerationRequest) -> HFGenerationResponse:
        if request.add_generation_prompt and request.continue_final_message:
            raise ValueError(
                "HF generation request cannot set both add_generation_prompt and "
                "continue_final_message"
            )

        template_kwargs: dict[str, Any] = {
            "tools": list(request.tools),
            "tokenize": False,
            "add_generation_prompt": request.add_generation_prompt,
        }
        if request.continue_final_message:
            template_kwargs["continue_final_message"] = True
        if request.chat_template is not None:
            template_kwargs["chat_template"] = request.chat_template

        prompt_text = self.processor.apply_chat_template(
            list(request.messages),
            **template_kwargs,
        )
        inputs = self.processor(text=str(prompt_text), return_tensors="pt")
        to_device = getattr(inputs, "to", None)
        if callable(to_device):
            inputs = to_device(self.model.device)

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
            self.processor.decode(
                generated_tokens,
                skip_special_tokens=skip_special_tokens,
                clean_up_tokenization_spaces=False,
            )
        )


def _model_loader_kwargs(config: HFBackendConfig) -> dict[str, Any]:
    loader_kwargs = config.model_loader_kwargs()
    if "torch_dtype" in loader_kwargs:
        loader_kwargs["dtype"] = loader_kwargs.pop("torch_dtype")
    return loader_kwargs
