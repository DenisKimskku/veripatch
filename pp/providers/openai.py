from __future__ import annotations

import os

from .openai_compatible import OpenAICompatiblePatchProposer


class OpenAIPatchProposer(OpenAICompatiblePatchProposer):
    def __init__(self) -> None:
        api_key = os.getenv("PP_OPENAI_API_KEY") or os.getenv("OPENAI_API_KEY")
        base_url = os.getenv("PP_OPENAI_BASE_URL") or "https://api.openai.com/v1"
        model = os.getenv("PP_OPENAI_MODEL") or "gpt-4.1-mini"
        temperature = float(os.getenv("PP_OPENAI_TEMPERATURE", "0"))
        max_tokens = int(os.getenv("PP_OPENAI_MAX_TOKENS", "2000"))
        timeout_sec = int(os.getenv("PP_OPENAI_TIMEOUT_SEC", "120"))

        super().__init__(
            api_key=api_key,
            base_url=base_url,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            timeout_sec=timeout_sec,
            require_api_key=True,
            provider_label="openai",
        )
