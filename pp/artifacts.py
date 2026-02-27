from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import random
import string
from typing import Any

from .models import CommandResult, ProposeOutput


def _session_id() -> str:
    suffix = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(6))
    return f"{os.getpid()}-{suffix}"


class ArtifactWriter:
    def __init__(self, workspace_root: Path) -> None:
        self.workspace_root = workspace_root
        self.session_id = _session_id()
        self.session_dir = workspace_root / ".pp-artifacts" / self.session_id
        self.proof_bundle_dir = self.session_dir / "proof_bundle"
        self.attempts_dir = self.proof_bundle_dir / "attempts"
        self.attempts_dir.mkdir(parents=True, exist_ok=True)

    def write_json(self, rel_path: str, payload: Any) -> Path:
        target = self.proof_bundle_dir / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return target

    def write_text(self, rel_path: str, text: str) -> Path:
        target = self.proof_bundle_dir / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        return target

    def write_command_result(self, rel_path: str, result: CommandResult) -> Path:
        payload = {
            "cmd": result.cmd,
            "exit_code": result.exit_code,
            "duration_sec": result.duration_sec,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
        return self.write_json(rel_path, payload)

    def write_proposal(self, attempt_no: int, proposal: ProposeOutput) -> Path:
        payload = {
            "diff": proposal.diff,
            "rationale": proposal.rationale,
            "risk_notes": proposal.risk_notes,
            "confidence": proposal.confidence,
            "raw_response": proposal.raw_response,
        }
        return self.write_json(f"attempts/{attempt_no}/proposed.json", payload)

    def write_environment(self, sandbox_backend: str, extra: dict[str, Any] | None = None) -> Path:
        payload = {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "sandbox_backend": sandbox_backend,
            "cwd": str(self.workspace_root),
        }
        if extra:
            payload.update(extra)
        return self.write_json("environment.json", payload)

    def write_summary(self, text: str) -> Path:
        return self.write_text("final_summary.md", text)

    def write_repro(self, payload: dict[str, Any]) -> Path:
        return self.write_json("repro.json", payload)

    def write_policy(self, payload: dict[str, Any]) -> Path:
        return self.write_json("policy.json", payload)
