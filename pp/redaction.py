from __future__ import annotations

import math
import re

_SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key\s*[=:]\s*)([A-Za-z0-9_\-]{8,})"),
    re.compile(r"(?i)(token\s*[=:]\s*)([A-Za-z0-9_\-]{8,})"),
    re.compile(r"(?i)(authorization:\s*bearer\s+)([A-Za-z0-9\-._~+/]+=*)"),
    re.compile(r"(?i)(password\s*[=:]\s*)([^\s\"']{4,})"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
]

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE_RE = re.compile(r"\b(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}\b")
_B64ISH_RE = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    total = len(s)
    return -sum((count / total) * math.log2(count / total) for count in freq.values())


def redact_text(text: str) -> str:
    out = text
    for pattern in _SECRET_PATTERNS:
        if pattern.groups >= 2:
            out = pattern.sub(lambda m: f"{m.group(1)}[REDACTED]", out)
        else:
            out = pattern.sub("[REDACTED_SECRET]", out)

    out = _EMAIL_RE.sub("[REDACTED_EMAIL]", out)
    out = _PHONE_RE.sub("[REDACTED_PHONE]", out)

    def _replace_entropy(match: re.Match[str]) -> str:
        token = match.group(0)
        if _entropy(token) >= 4.0:
            return "[REDACTED_HIGH_ENTROPY]"
        return token

    out = _B64ISH_RE.sub(_replace_entropy, out)
    return out
