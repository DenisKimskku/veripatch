from __future__ import annotations

import json
import re
from typing import Any
from urllib import request

from ..models import ProposeOutput
from .base import PatchProposer, ProposalInput


class OpenAICompatiblePatchProposer(PatchProposer):
    def __init__(
        self,
        *,
        api_key: str | None,
        base_url: str,
        model: str,
        temperature: float,
        max_tokens: int,
        timeout_sec: int,
        require_api_key: bool,
        provider_label: str,
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout_sec = timeout_sec
        self.provider_label = provider_label

        if require_api_key and not self.api_key:
            raise RuntimeError(
                f"{provider_label} provider requires API key configuration for authenticated access"
            )

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
            "You are veripatch patch proposer.\n"
            "Return STRICT JSON object with keys: diff, rationale, risk_notes, confidence.\n"
            "Rules:\n"
            "1) diff must be valid unified diff and only include files in allowlist.\n"
            "2) include file headers for every changed file: '--- a/<path>' and '+++ b/<path>'.\n"
            "3) never return hunk-only patches (starting with '@@').\n"
            "4) minimize changes; avoid refactors.\n"
            "5) do not propose dependency or lockfile changes unless explicitly required.\n"
            "6) if no safe fix is possible, set diff to empty string and explain.\n\n"
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

        headers = {
            "Content-Type": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        req = request.Request(
            url=f"{self.base_url}/chat/completions",
            data=json.dumps(body).encode("utf-8"),
            method="POST",
            headers=headers,
        )

        with request.urlopen(req, timeout=self.timeout_sec) as resp:
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
