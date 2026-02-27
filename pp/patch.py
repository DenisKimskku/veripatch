from __future__ import annotations

from dataclasses import dataclass, field
import difflib
from fnmatch import fnmatch
from pathlib import Path
import re
from typing import Iterable

from .config import Policy


_HUNK_RE = re.compile(r"^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@")


@dataclass
class Hunk:
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    lines: list[str] = field(default_factory=list)


@dataclass
class FilePatch:
    old_path: str
    new_path: str
    hunks: list[Hunk] = field(default_factory=list)

    @property
    def rel_path(self) -> str:
        candidate = self.new_path if self.new_path != "/dev/null" else self.old_path
        if candidate.startswith("a/") or candidate.startswith("b/"):
            return candidate[2:]
        return candidate


@dataclass
class ParsedPatch:
    files: list[FilePatch]


def _strip_prefix(path: str) -> str:
    path = path.strip()
    if path.startswith("a/") or path.startswith("b/"):
        return path[2:]
    return path


def parse_unified_diff(diff_text: str) -> ParsedPatch:
    lines = diff_text.splitlines()
    idx = 0
    files: list[FilePatch] = []

    current: FilePatch | None = None
    while idx < len(lines):
        line = lines[idx]
        if line.startswith("diff --git"):
            idx += 1
            continue
        if line.startswith("--- "):
            old_path = line[4:].strip().split("\t", 1)[0]
            idx += 1
            if idx >= len(lines) or not lines[idx].startswith("+++ "):
                raise ValueError("Malformed patch: expected +++ line")
            new_path = lines[idx][4:].strip().split("\t", 1)[0]
            current = FilePatch(old_path=old_path, new_path=new_path, hunks=[])
            files.append(current)
            idx += 1
            continue
        if line.startswith("@@ "):
            if current is None:
                raise ValueError("Malformed patch: hunk without file header")
            match = _HUNK_RE.match(line)
            if not match:
                raise ValueError(f"Malformed hunk header: {line}")
            hunk = Hunk(
                old_start=int(match.group(1)),
                old_count=int(match.group(2) or "1"),
                new_start=int(match.group(3)),
                new_count=int(match.group(4) or "1"),
                lines=[],
            )
            idx += 1
            while idx < len(lines):
                hline = lines[idx]
                if hline.startswith(("@@ ", "--- ", "diff --git")):
                    break
                if hline.startswith("\\ No newline at end of file"):
                    idx += 1
                    continue
                if not hline.startswith((" ", "+", "-")):
                    raise ValueError(f"Malformed hunk line: {hline}")
                hunk.lines.append(hline)
                idx += 1
            current.hunks.append(hunk)
            continue
        idx += 1

    if not files:
        raise ValueError("Patch did not contain any files")

    return ParsedPatch(files=files)


def _is_path_allowed(rel_path: str, policy: Policy) -> bool:
    rel_path = rel_path.replace("\\", "/").lstrip("/")
    allowed = any(fnmatch(rel_path, pattern) for pattern in policy.write_allowlist)
    denied = any(fnmatch(rel_path, pattern) for pattern in policy.deny_write)
    return allowed and not denied


def patch_stats(diff_text: str) -> tuple[int, int]:
    parsed = parse_unified_diff(diff_text)
    return len(parsed.files), len(diff_text.encode("utf-8"))


def apply_unified_diff(diff_text: str, workspace_root: Path, policy: Policy) -> list[str]:
    parsed = parse_unified_diff(diff_text)

    if len(parsed.files) > policy.limits.max_files_changed:
        raise ValueError(
            f"Patch changes {len(parsed.files)} files, above max {policy.limits.max_files_changed}"
        )

    if len(diff_text.encode("utf-8")) > policy.limits.max_patch_bytes:
        raise ValueError(
            f"Patch size exceeds {policy.limits.max_patch_bytes} bytes"
        )

    changed_paths: list[str] = []

    for file_patch in parsed.files:
        rel_path = file_patch.rel_path
        if rel_path == "/dev/null":
            raise ValueError("Unsupported patch target path")
        rel_path = _strip_prefix(rel_path)

        if not _is_path_allowed(rel_path, policy):
            raise ValueError(f"Patch path is not allowed by policy: {rel_path}")

        path = workspace_root / rel_path
        old_is_dev_null = file_patch.old_path == "/dev/null"
        new_is_dev_null = file_patch.new_path == "/dev/null"

        if old_is_dev_null:
            original_lines: list[str] = []
            had_trailing_newline = True
        else:
            if not path.exists():
                raise ValueError(f"Target file does not exist: {rel_path}")
            raw = path.read_text(encoding="utf-8", errors="replace")
            had_trailing_newline = raw.endswith("\n")
            original_lines = raw.splitlines()

        lines = list(original_lines)
        offset = 0
        for hunk in file_patch.hunks:
            idx = hunk.old_start - 1 + offset
            if hunk.old_count == 0:
                idx = max(0, idx + 1)
            if idx < 0:
                idx = 0

            cursor = idx
            replacement: list[str] = []
            for hline in hunk.lines:
                marker, payload = hline[0], hline[1:]
                if marker == " ":
                    if cursor >= len(lines) or lines[cursor] != payload:
                        raise ValueError(f"Context mismatch applying patch to {rel_path}")
                    replacement.append(lines[cursor])
                    cursor += 1
                elif marker == "-":
                    if cursor >= len(lines) or lines[cursor] != payload:
                        raise ValueError(f"Removal mismatch applying patch to {rel_path}")
                    cursor += 1
                elif marker == "+":
                    replacement.append(payload)

            consumed = cursor - idx
            lines[idx:cursor] = replacement
            offset += len(replacement) - consumed

        if new_is_dev_null:
            if path.exists():
                path.unlink()
            changed_paths.append(rel_path)
            continue

        path.parent.mkdir(parents=True, exist_ok=True)
        final_text = "\n".join(lines)
        if lines and had_trailing_newline:
            final_text += "\n"
        if old_is_dev_null and lines:
            final_text += "\n"
        path.write_text(final_text, encoding="utf-8")
        changed_paths.append(rel_path)

    return changed_paths


def _iter_files(root: Path) -> Iterable[Path]:
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(root).as_posix()
        if rel.startswith(".git/") or rel.startswith(".pp-artifacts/"):
            continue
        if "/__pycache__/" in f"/{rel}/":
            continue
        yield p


def diff_between_dirs(base_dir: Path, new_dir: Path) -> str:
    base_files = {p.relative_to(base_dir).as_posix(): p for p in _iter_files(base_dir)}
    new_files = {p.relative_to(new_dir).as_posix(): p for p in _iter_files(new_dir)}

    all_paths = sorted(set(base_files) | set(new_files))
    chunks: list[str] = []

    for rel in all_paths:
        base_path = base_files.get(rel)
        new_path = new_files.get(rel)

        if base_path and new_path:
            base_text = base_path.read_text(encoding="utf-8", errors="replace").splitlines()
            new_text = new_path.read_text(encoding="utf-8", errors="replace").splitlines()
            if base_text == new_text:
                continue
            diff_lines = list(
                difflib.unified_diff(
                    base_text,
                    new_text,
                    fromfile=f"a/{rel}",
                    tofile=f"b/{rel}",
                    lineterm="",
                )
            )
        elif base_path and not new_path:
            base_text = base_path.read_text(encoding="utf-8", errors="replace").splitlines()
            diff_lines = list(
                difflib.unified_diff(
                    base_text,
                    [],
                    fromfile=f"a/{rel}",
                    tofile="/dev/null",
                    lineterm="",
                )
            )
        else:
            new_text = new_path.read_text(encoding="utf-8", errors="replace").splitlines() if new_path else []
            diff_lines = list(
                difflib.unified_diff(
                    [],
                    new_text,
                    fromfile="/dev/null",
                    tofile=f"b/{rel}",
                    lineterm="",
                )
            )

        if diff_lines:
            chunks.append("\n".join(diff_lines))

    return "\n".join(chunks).strip() + ("\n" if chunks else "")


def render_patch_from_filepatches(files: list[FilePatch]) -> str:
    if not files:
        return ""
    out: list[str] = []
    for fp in files:
        out.append(f"--- {fp.old_path}")
        out.append(f"+++ {fp.new_path}")
        for h in fp.hunks:
            old_count = h.old_count
            new_count = h.new_count
            out.append(f"@@ -{h.old_start},{old_count} +{h.new_start},{new_count} @@")
            out.extend(h.lines)
    return "\n".join(out).strip() + "\n"
