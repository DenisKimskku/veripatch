from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

_IGNORE_PREFIXES = (
    ".git/",
    ".pp-artifacts/",
    "__pycache__/",
    ".pytest_cache/",
)


def _run_git(root: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def _is_git_repo(root: Path) -> bool:
    proc = _run_git(root, ["rev-parse", "--is-inside-work-tree"])
    return proc.returncode == 0 and proc.stdout.strip() == "true"


def collect_git_metadata(root: Path) -> dict[str, Any]:
    out: dict[str, Any] = {
        "is_git_repo": False,
        "git_commit": None,
        "git_branch": None,
        "git_remote_url": None,
        "git_dirty": None,
        "git_diff": None,
    }

    if not _is_git_repo(root):
        return out

    out["is_git_repo"] = True

    head = _run_git(root, ["rev-parse", "HEAD"])
    if head.returncode == 0:
        out["git_commit"] = head.stdout.strip() or None

    branch = _run_git(root, ["rev-parse", "--abbrev-ref", "HEAD"])
    if branch.returncode == 0:
        out["git_branch"] = branch.stdout.strip() or None

    remote = _run_git(root, ["config", "--get", "remote.origin.url"])
    if remote.returncode == 0:
        out["git_remote_url"] = remote.stdout.strip() or None

    status = _run_git(root, ["status", "--porcelain"])
    if status.returncode == 0:
        dirty = bool(status.stdout.strip())
        out["git_dirty"] = dirty
        if dirty:
            diff = _run_git(root, ["diff", "--no-color"])
            if diff.returncode == 0:
                out["git_diff"] = diff.stdout

    return out


def _should_skip(rel_path: str) -> bool:
    if rel_path in {".git", ".pp-artifacts", "__pycache__", ".pytest_cache"}:
        return True
    wrapped = f"/{rel_path}/"
    return any(f"/{token}" in wrapped for token in ("/.git/", "/.pp-artifacts/", "/__pycache__/", "/.pytest_cache/"))


def build_workspace_manifest(root: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if _should_skip(rel):
            continue

        h = hashlib.sha256()
        size = 0
        with path.open("rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                h.update(chunk)

        records.append(
            {
                "path": rel,
                "bytes": size,
                "sha256": h.hexdigest(),
            }
        )

    return records


def manifest_sha256(manifest_files: list[dict[str, Any]]) -> str:
    payload = json.dumps({"files": manifest_files}, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
