from __future__ import annotations

import shutil
import tempfile
from dataclasses import replace
from pathlib import Path

from .config import Policy
from .patch import (
    FilePatch,
    apply_unified_diff,
    parse_unified_diff,
    render_patch_from_filepatches,
)
from .runner import Sandbox, run_command


def _clone_files(file_patches: list[FilePatch]) -> list[FilePatch]:
    cloned: list[FilePatch] = []
    for fp in file_patches:
        cloned.append(
            FilePatch(
                old_path=fp.old_path,
                new_path=fp.new_path,
                hunks=[replace(h, lines=list(h.lines)) for h in fp.hunks],
            )
        )
    return cloned


def minimize_patch_hunks(
    patch_text: str,
    baseline_root: Path,
    verify_cmd: str,
    timeout_sec: int,
    policy: Policy,
    execution_sandbox: Sandbox | None = None,
) -> str:
    if not patch_text.strip():
        return patch_text

    parsed = parse_unified_diff(patch_text)
    current_files = _clone_files(parsed.files)

    made_progress = True
    while made_progress:
        made_progress = False
        for file_idx, file_patch in enumerate(list(current_files)):
            for hunk_idx in range(len(file_patch.hunks)):
                candidate_files = _clone_files(current_files)
                candidate_files[file_idx].hunks.pop(hunk_idx)
                candidate_files = [fp for fp in candidate_files if fp.hunks]
                candidate_patch = render_patch_from_filepatches(candidate_files)

                temp_root = Path(tempfile.mkdtemp(prefix="pp-minimize-")) / "workspace"
                shutil.copytree(
                    baseline_root,
                    temp_root,
                    ignore=shutil.ignore_patterns(".git", ".pp-artifacts", "__pycache__", ".pytest_cache"),
                )

                if candidate_patch.strip():
                    try:
                        apply_unified_diff(candidate_patch, temp_root, policy)
                    except Exception:
                        shutil.rmtree(temp_root.parent, ignore_errors=True)
                        continue

                verify_sandbox: Sandbox | None = None
                if execution_sandbox is not None:
                    verify_sandbox = replace(
                        execution_sandbox,
                        root=temp_root,
                        control_root=temp_root,
                        cleanup_token=None,
                    )
                verify = run_command(verify_cmd, temp_root, timeout_sec, sandbox=verify_sandbox)
                shutil.rmtree(temp_root.parent, ignore_errors=True)

                if verify.exit_code == 0:
                    current_files = candidate_files
                    made_progress = True
                    break
            if made_progress:
                break

    return render_patch_from_filepatches(current_files) if current_files else ""
