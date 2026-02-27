from __future__ import annotations

import os

from .base import PatchProposer
from .local import LocalPatchProposer
from .openai import OpenAIPatchProposer
from .stub import StubPatchProposer


def create_provider(name: str | None = None) -> PatchProposer:
    provider_name = (name or os.getenv("PP_PROVIDER") or "stub").strip().lower()
    if provider_name == "openai":
        return OpenAIPatchProposer()
    if provider_name in {"local", "local-openai", "vllm", "lmstudio"}:
        return LocalPatchProposer()
    if provider_name == "stub":
        return StubPatchProposer()
    raise ValueError(f"Unknown provider: {provider_name}")
