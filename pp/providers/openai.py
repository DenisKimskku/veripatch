from __future__ import annotations

import json
import os
import re
from typing import Any
from urllib import request

from ..models import ProposeOutput
from .base import PatchProposer, ProposalInput


class OpenAIPatchProposer(PatchProposer):
    def __init__(self) -> None:
        self.api_key = os.getenv("PP_OPENAI_API_KEY") or os.getenv("OPENAI_API_KEY")
        self.base_url = (os.getenv("PP_OPENAI_BASE_URL") or "https://api.openai.com/v1").rstrip("/")
        self.model = os.getenv("PP_OPENAI_MODEL") or "gpt-4.1-mini"
        self.temperature = float(os.getenv("PP_OPENAI_TEMPERATURE", "0"))
        self.max_tokens = int(os.getenv("PP_OPENAI_MAX_TOKENS", "2000"))

        if not self.api_key:
            raise RuntimeError("PP_OPENAI_API_KEY or OPENAI_API_KEY is required for openai provider")

    def _build_prompt(self, payload: ProposalInput) -> str:
        snippets = []
        for key, snippet in payload.context.snippets.items():
            if snippet:
                snippets.append(f"### {key}\n{snippet}")

        assertions = "\n".join(f"- {a}" for a in payload.context.failing_assertions)
        prev = "\n".join(f"- {x}" for x in payload.previous_attempts[-3:])
        allow = "\n".join(f"- {p}" for p in payload.write_allowlist)
        deny = "\n".join(f"- {p}" for p in payload.deny_write)
        snippets_block = "\n\n".join(snippets)[:20000]

        return (
            "You are Patch & Prove patch proposer.\n"
            "Return STRICT JSON object with keys: diff, rationale, risk_notes, confidence.\n"
            "Rules:\n"
            "1) diff must be unified diff and only include files in allowlist.\n"
            "2) minimize changes; avoid refactors.\n"
            "3) do not propose dependency or lockfile changes unless explicitly required.\n"
            "4) if no safe fix is possible, set diff to empty string and explain.\n\n"
            f"Failing command: {payload.command}\n"
            f"Allowlist:\n{allow or '- (none)'}\n"
            f"Denylist:\n{deny or '- (none)'}\n"
            f"Recent attempt errors:\n{prev or '- (none)'}\n"
            f"Failing assertions:\n{assertions or '- (none)'}\n\n"
            f"Failure output:\n{payload.failure_output[:12000]}\n\n"
            f"Context snippets:\n{snippets_block}\n"
        )

    def _extract_json(self, content: str) -> dict[str, Any]:
        text = content.strip()
        if text.startswith("```"):
            text = re.sub(r"^```[a-zA-Z0-9_\-]*\n", "", text)
            text = re.sub(r"\n```$", "", text)
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

        match = re.search(r"\{.*\}", text, re.DOTALL)
        if not match:
            raise RuntimeError("Model did not return a JSON object")
        parsed = json.loads(match.group(0))
        if not isinstance(parsed, dict):
            raise RuntimeError("Invalid JSON response type")
        return parsed

    def propose(self, payload: ProposalInput) -> ProposeOutput:
        prompt = self._build_prompt(payload)
        body = {
            "model": self.model,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "messages": [
                {"role": "system", "content": "Generate minimal unified diff patches with strict JSON output."},
                {"role": "user", "content": prompt},
            ],
        }

        req = request.Request(
            url=f"{self.base_url}/chat/completions",
            data=json.dumps(body).encode("utf-8"),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
        )

        with request.urlopen(req, timeout=120) as resp:
            raw = resp.read().decode("utf-8", errors="replace")

        response = json.loads(raw)
        content = response["choices"][0]["message"]["content"]
        parsed = self._extract_json(content)

        diff = str(parsed.get("diff", ""))
        rationale = str(parsed.get("rationale", ""))
        risk_notes = str(parsed.get("risk_notes", ""))
        confidence_raw = parsed.get("confidence")
        confidence: float | None = None
        if isinstance(confidence_raw, (float, int)):
            confidence = float(confidence_raw)

        return ProposeOutput(
            diff=diff,
            rationale=rationale,
            risk_notes=risk_notes,
            confidence=confidence,
            raw_response=content,
        )
