from __future__ import annotations

import os

from .openai_compatible import OpenAICompatiblePatchProposer


class LocalPatchProposer(OpenAICompatiblePatchProposer):
    """OpenAI-compatible local model provider.

    Intended for local inference servers such as vLLM, llama.cpp, or LM Studio.
    """

    def __init__(self) -> None:
        api_key = os.getenv("PP_LOCAL_API_KEY") or os.getenv("PP_OPENAI_API_KEY")
        base_url = os.getenv("PP_LOCAL_BASE_URL") or "http://127.0.0.1:8000/v1"
        model = os.getenv("PP_LOCAL_MODEL") or "Qwen/Qwen2.5-Coder-7B-Instruct"
        temperature = float(os.getenv("PP_LOCAL_TEMPERATURE", "0"))
        max_tokens = int(os.getenv("PP_LOCAL_MAX_TOKENS", "2000"))
        timeout_sec = int(os.getenv("PP_LOCAL_TIMEOUT_SEC", "240"))

        super().__init__(
            api_key=api_key,
            base_url=base_url,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            timeout_sec=timeout_sec,
            require_api_key=False,
            provider_label="local",
        )
