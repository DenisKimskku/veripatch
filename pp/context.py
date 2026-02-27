from __future__ import annotations

import re
from pathlib import Path

from .models import ContextSlice, Location

_TRACEBACK_FILE_RE = re.compile(r'File "(?P<file>.+?)", line (?P<line>\d+)')
_COMPILER_RE = re.compile(r"(?P<file>[\w./\\-]+):(\s)?(?P<line>\d+)(:(?P<col>\d+))?")
_ASSERT_RE = re.compile(r"(AssertionError:.*|E\s+assert\s+.*|FAILED\s+.*)")


def _to_relative(path: Path, workspace_root: Path) -> str | None:
    try:
        rel = path.resolve().relative_to(workspace_root.resolve())
        return rel.as_posix()
    except Exception:
        return None


def _resolve_path(raw: str, workspace_root: Path, container_workdir: str | None) -> Path:
    p = Path(raw)
    if p.is_absolute():
        if container_workdir:
            container_root = Path(container_workdir)
            try:
                rel = p.relative_to(container_root)
                return (workspace_root / rel).resolve()
            except Exception:
                pass
        return p.resolve()
    return (workspace_root / p).resolve()


def _extract_locations(text: str, workspace_root: Path, container_workdir: str | None) -> list[Location]:
    locations: list[Location] = []
    seen: set[tuple[str, int]] = set()

    for match in _TRACEBACK_FILE_RE.finditer(text):
        raw = match.group("file")
        line = int(match.group("line"))
        p = _resolve_path(raw, workspace_root, container_workdir)
        rel = _to_relative(p, workspace_root)
        if rel is None:
            continue
        key = (rel, line)
        if key in seen:
            continue
        seen.add(key)
        locations.append(Location(file=rel, line=line, reason="traceback"))

    for match in _COMPILER_RE.finditer(text):
        raw = match.group("file")
        line = int(match.group("line"))
        p = _resolve_path(raw, workspace_root, container_workdir)
        rel = _to_relative(p, workspace_root)
        if rel is None:
            continue
        key = (rel, line)
        if key in seen:
            continue
        seen.add(key)
        locations.append(Location(file=rel, line=line, reason="diagnostic"))

    return locations[:20]


def _snippet_for_location(workspace_root: Path, rel_path: str, line_no: int, radius: int = 25) -> str:
    path = workspace_root / rel_path
    if not path.exists() or not path.is_file():
        return ""

    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    if not lines:
        return ""

    start = max(1, line_no - radius)
    end = min(len(lines), line_no + radius)
    out: list[str] = []
    for i in range(start, end + 1):
        marker = ">>" if i == line_no else "  "
        out.append(f"{marker} {i:5d} | {lines[i - 1]}")
    return "\n".join(out)


def extract_context(
    result_text: str,
    workspace_root: Path,
    container_workdir: str | None = None,
) -> ContextSlice:
    locations = _extract_locations(result_text, workspace_root, container_workdir)
    snippets: dict[str, str] = {}
    for loc in locations:
        key = f"{loc.file}:{loc.line}"
        snippets[key] = _snippet_for_location(workspace_root, loc.file, loc.line)

    assertions = [m.group(1).strip() for m in _ASSERT_RE.finditer(result_text)]
    return ContextSlice(locations=locations, snippets=snippets, failing_assertions=assertions[:20])
