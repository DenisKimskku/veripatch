from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from ..models import ContextSlice, ProposeOutput


@dataclass
class ProposalInput:
    command: str
    failure_output: str
    context: ContextSlice
    previous_attempts: list[str]
    write_allowlist: list[str]
    deny_write: list[str]
    editable_files: dict[str, str] = field(default_factory=dict)


class PatchProposer(ABC):
    @abstractmethod
    def propose(self, payload: ProposalInput) -> ProposeOutput:
        raise NotImplementedError
