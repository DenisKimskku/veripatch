from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class CommandResult:
    cmd: str
    exit_code: int
    stdout: str
    stderr: str
    duration_sec: float

    @property
    def combined_output(self) -> str:
        if self.stdout and self.stderr:
            return f"{self.stdout}\n{self.stderr}"
        return self.stdout or self.stderr


@dataclass
class Location:
    file: str
    line: int
    reason: str


@dataclass
class ContextSlice:
    locations: list[Location] = field(default_factory=list)
    snippets: dict[str, str] = field(default_factory=dict)
    failing_assertions: list[str] = field(default_factory=list)


@dataclass
class ProposeOutput:
    diff: str
    rationale: str
    risk_notes: str
    confidence: float | None = None
    raw_response: str | None = None


@dataclass
class AttemptRecord:
    number: int
    proposed: ProposeOutput | None
    apply_ok: bool
    verify_result: CommandResult | None
    error: str | None = None


@dataclass
class RunSummary:
    success: bool
    attempts_used: int
    final_patch_path: Path
    proof_bundle_dir: Path
    final_result: CommandResult
    attempt_records: list[AttemptRecord]
    extra: dict[str, Any] = field(default_factory=dict)
