from __future__ import annotations

from ..models import ProposeOutput
from .base import PatchProposer, ProposalInput


class StubPatchProposer(PatchProposer):
    """Deterministic fallback provider.

    This keeps the engine runnable offline without model credentials.
    """

    def propose(self, payload: ProposalInput) -> ProposeOutput:
        del payload
        return ProposeOutput(
            diff="",
            rationale="Stub provider returns no patch.",
            risk_notes="No changes proposed.",
            confidence=0.0,
            raw_response="stub",
        )
