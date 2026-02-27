from __future__ import annotations

import difflib
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

        editable_files = []
        for path, content in payload.editable_files.items():
            if not content:
                continue
            editable_files.append(f"### {path}\n```\n{content}\n```")

        assertions = "\n".join(f"- {a}" for a in payload.context.failing_assertions)
        prev = "\n".join(f"- {x}" for x in payload.previous_attempts[-3:])
        allow = "\n".join(f"- {p}" for p in payload.write_allowlist)
        deny = "\n".join(f"- {p}" for p in payload.deny_write)
        snippets_block = "\n\n".join(snippets)[:20000]
        editable_block = "\n\n".join(editable_files)[:24000]

        return (
            "You are veripatch patch proposer.\n"
            "Return STRICT JSON object with keys: diff, rationale, risk_notes, confidence.\n"
            "Rules:\n"
            "1) diff must be valid unified diff and only include files in allowlist.\n"
            "2) include file headers for every changed file: '--- a/<path>' and '+++ b/<path>'.\n"
            "3) never return hunk-only patches (starting with '@@').\n"
            "4) minimize changes; avoid refactors.\n"
            "5) do not propose dependency or lockfile changes unless explicitly required.\n"
            "6) deleted/context lines in each hunk must exactly match snippet text.\n"
            "7) if previous errors mention context mismatch, use 'Current file snapshots' as canonical source.\n"
            "8) if needed, rewrite the whole target file in one patch hunk using exact old lines from snapshot.\n"
            "9) do not return empty diff when tests still fail and an allowlisted file is available.\n"
            "10) every hunk must include at least one '-' or '+' line; context-only hunks are rejected.\n"
            "11) the diff must make a real code change (no no-op patches).\n"
            "12) if editable files are provided, do not claim missing context; use those files directly.\n"
            "13) if no safe fix is possible, set diff to empty string and explain why constraints block edits.\n\n"
            "Unified diff example (required shape):\n"
            "--- a/text_utils.py\n"
            "+++ b/text_utils.py\n"
            "@@ -1,2 +1,2 @@\n"
            " def slugify(text):\n"
            "-    return text.strip().lower().replace(\" \", \"\")\n"
            "+    return text.strip().lower().replace(\" \", \"-\")\n\n"
            f"Failing command: {payload.command}\n"
            f"Editable file snapshots (canonical; you may edit ONLY these files):\n{editable_block or '(none)'}\n\n"
            f"Allowlist:\n{allow or '- (none)'}\n"
            f"Denylist:\n{deny or '- (none)'}\n"
            f"Recent attempt errors:\n{prev or '- (none)'}\n"
            f"Failing assertions:\n{assertions or '- (none)'}\n\n"
            f"Failure output:\n{payload.failure_output[:12000]}\n\n"
            f"Context snippets:\n{snippets_block}\n"
        )

    def _build_retry_prompt(self, payload: ProposalInput, previous_response: str) -> str:
        base = self._build_prompt(payload)
        return (
            "Your previous response was rejected because the diff was empty or ineffective.\n"
            "Return a NON-EMPTY diff now.\n"
            "Hard requirements for this retry:\n"
            "- edit at least one line in an editable file snapshot.\n"
            "- include both '-' and '+' changed lines for replacements.\n"
            "- if easiest, rewrite the whole file with one hunk.\n"
            "- do not repeat prior rejected output.\n\n"
            f"Rejected response:\n{previous_response[:4000]}\n\n"
            f"{base}"
        )

    def _request_completion(self, prompt: str) -> str:
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
        return response["choices"][0]["message"]["content"]

    def _build_rewrite_prompt(self, payload: ProposalInput, path: str, current_content: str) -> str:
        return (
            "Your previous responses did not provide a usable diff.\n"
            "Return STRICT JSON with keys: path, content, rationale, risk_notes, confidence.\n"
            "Rules:\n"
            f"1) path must be exactly '{path}'.\n"
            "2) content must be the complete replacement file text.\n"
            "3) content must keep valid syntax and only include minimal needed changes.\n"
            "4) do not include markdown fences inside JSON values.\n\n"
            f"Failing command: {payload.command}\n"
            f"Failure output:\n{payload.failure_output[:12000]}\n\n"
            f"Current file snapshot ({path}):\n```\n{current_content}\n```\n"
        )

    def _full_file_diff(self, path: str, before: str, after: str) -> str:
        if before == after:
            return ""
        before_lines = before.splitlines()
        after_lines = after.splitlines()
        diff_lines = list(
            difflib.unified_diff(
                before_lines,
                after_lines,
                fromfile=f"a/{path}",
                tofile=f"b/{path}",
                lineterm="",
            )
        )
        if not diff_lines:
            return ""
        return "\n".join(diff_lines).strip() + "\n"

    def _diff_has_effective_edits(self, diff: str) -> bool:
        added: list[str] = []
        removed: list[str] = []
        for line in diff.splitlines():
            if line.startswith(("diff --git ", "--- ", "+++ ", "@@ ", "\\ No newline")):
                continue
            if line.startswith("+"):
                added.append(line[1:])
            elif line.startswith("-"):
                removed.append(line[1:])
        if not added and not removed:
            return False
        if added == removed:
            return False
        return True

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
        content = self._request_completion(self._build_prompt(payload))
        parsed = self._extract_json(content)
        diff = str(parsed.get("diff", ""))

        if payload.editable_files and not self._diff_has_effective_edits(diff):
            retry_content = self._request_completion(self._build_retry_prompt(payload, content))
            retry_parsed = self._extract_json(retry_content)
            retry_diff = str(retry_parsed.get("diff", ""))
            if self._diff_has_effective_edits(retry_diff):
                content = retry_content
                parsed = retry_parsed
                diff = retry_diff

        if payload.editable_files and not self._diff_has_effective_edits(diff) and len(payload.editable_files) == 1:
            target_path, target_content = next(iter(payload.editable_files.items()))
            rewrite_content = self._request_completion(
                self._build_rewrite_prompt(payload, target_path, target_content)
            )
            rewrite_parsed = self._extract_json(rewrite_content)
            rewrite_path = str(rewrite_parsed.get("path", "")).strip()
            if rewrite_path.startswith("a/") or rewrite_path.startswith("b/"):
                rewrite_path = rewrite_path[2:]
            rewrite_body = str(rewrite_parsed.get("content", ""))
            if rewrite_path == target_path and rewrite_body:
                rewrite_diff = self._full_file_diff(target_path, target_content, rewrite_body)
                if self._diff_has_effective_edits(rewrite_diff):
                    content = rewrite_content
                    parsed = {
                        "diff": rewrite_diff,
                        "rationale": rewrite_parsed.get("rationale", parsed.get("rationale", "")),
                        "risk_notes": rewrite_parsed.get("risk_notes", parsed.get("risk_notes", "")),
                        "confidence": rewrite_parsed.get("confidence", parsed.get("confidence")),
                    }
                    diff = rewrite_diff

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
