from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from .config import Policy
from .models import CommandResult


@dataclass
class Sandbox:
    root: Path
    backend: str  # native | container
    workspace_backend: str  # copy | git_worktree
    control_root: Path
    cleanup_token: str | None = None
    container_runtime: str | None = None
    container_image: str | None = None
    container_workdir: str = "/workspace"
    network: str = "deny"
    cpu_limit: str | None = None
    memory_limit: str | None = None
    container_image_id: str | None = None


def is_git_repo(path: Path) -> bool:
    proc = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "--is-inside-work-tree"],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode == 0 and proc.stdout.strip() == "true"


def is_git_clean(path: Path) -> bool:
    proc = subprocess.run(
        ["git", "-C", str(path), "status", "--porcelain"],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode == 0 and not proc.stdout.strip()


def _copy_sandbox(workspace_root: Path) -> Sandbox:
    tmp_parent = Path(tempfile.mkdtemp(prefix="pp-sandbox-"))
    sandbox_root = tmp_parent / "workspace"
    if sandbox_root.exists():
        shutil.rmtree(sandbox_root)
    shutil.copytree(
        workspace_root,
        sandbox_root,
        ignore=shutil.ignore_patterns(".git", ".pp-artifacts", "__pycache__", ".pytest_cache"),
    )
    return Sandbox(
        root=sandbox_root,
        backend="native",
        workspace_backend="copy",
        control_root=workspace_root,
        cleanup_token=str(tmp_parent),
    )


def _git_worktree_sandbox(workspace_root: Path) -> Sandbox:
    tmp_parent = Path(tempfile.mkdtemp(prefix="pp-sandbox-"))
    sandbox_root = tmp_parent / "workspace"
    proc = subprocess.run(
        ["git", "-C", str(workspace_root), "worktree", "add", "--detach", str(sandbox_root), "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"Failed to create git worktree sandbox: {proc.stderr.strip()}")

    control_root_proc = subprocess.run(
        ["git", "-C", str(workspace_root), "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=False,
    )
    control_root = workspace_root
    if control_root_proc.returncode == 0 and control_root_proc.stdout.strip():
        control_root = Path(control_root_proc.stdout.strip())

    return Sandbox(
        root=sandbox_root,
        backend="native",
        workspace_backend="git_worktree",
        control_root=control_root,
        cleanup_token=str(sandbox_root),
    )


def _container_image_id(runtime: str, image: str) -> str | None:
    proc = subprocess.run(
        [runtime, "image", "inspect", image, "--format", "{{.Id}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode == 0:
        out = proc.stdout.strip()
        return out or None
    return None


def create_sandbox(workspace_root: Path, policy: Policy) -> Sandbox:
    requested = (policy.sandbox.backend or "auto").strip().lower()

    if requested not in {"auto", "copy", "git_worktree", "container"}:
        raise RuntimeError(f"Invalid policy.sandbox.backend: {requested}")

    if requested == "container":
        runtime = policy.sandbox.container_runtime
        if shutil.which(runtime) is None:
            raise RuntimeError(
                f"Container backend requested but runtime '{runtime}' is not available in PATH"
            )
        sandbox = _copy_sandbox(workspace_root)
        sandbox.backend = "container"
        sandbox.container_runtime = runtime
        sandbox.container_image = policy.sandbox.container_image
        sandbox.container_workdir = policy.sandbox.container_workdir
        sandbox.network = policy.network
        sandbox.cpu_limit = policy.sandbox.cpu_limit
        sandbox.memory_limit = policy.sandbox.memory_limit
        sandbox.container_image_id = _container_image_id(runtime, policy.sandbox.container_image)
        return sandbox

    if requested == "copy":
        return _copy_sandbox(workspace_root)

    if requested == "git_worktree":
        if not is_git_repo(workspace_root):
            raise RuntimeError("policy.sandbox.backend=git_worktree requires a git repository")
        return _git_worktree_sandbox(workspace_root)

    # auto
    if is_git_repo(workspace_root) and is_git_clean(workspace_root):
        return _git_worktree_sandbox(workspace_root)
    return _copy_sandbox(workspace_root)


def cleanup_sandbox(sandbox: Sandbox) -> None:
    if not sandbox.cleanup_token:
        return

    token = Path(sandbox.cleanup_token)
    if sandbox.workspace_backend == "git_worktree":
        proc = subprocess.run(
            ["git", "-C", str(sandbox.control_root), "worktree", "remove", "--force", str(sandbox.root)],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            # fallback cleanup to avoid leaks
            shutil.rmtree(sandbox.root.parent, ignore_errors=True)
        else:
            shutil.rmtree(sandbox.root.parent, ignore_errors=True)
        return

    shutil.rmtree(token, ignore_errors=True)


def _build_container_command(
    cmd: str,
    cwd: Path,
    sandbox: Sandbox,
    argv: list[str] | None = None,
) -> list[str]:
    runtime = sandbox.container_runtime or "docker"
    image = sandbox.container_image or "python:3.11-slim"
    workdir = sandbox.container_workdir or "/workspace"

    args: list[str] = [
        runtime,
        "run",
        "--rm",
        "--workdir",
        workdir,
        "--volume",
        f"{cwd}:{workdir}",
        "-e",
        "CI=1",
    ]

    if hasattr(os, "getuid") and hasattr(os, "getgid"):
        args += ["--user", f"{os.getuid()}:{os.getgid()}"]

    if sandbox.network == "deny":
        args += ["--network", "none"]

    if sandbox.cpu_limit:
        args += ["--cpus", str(sandbox.cpu_limit)]

    if sandbox.memory_limit:
        args += ["--memory", str(sandbox.memory_limit)]

    if argv:
        args += [image, *argv]
    else:
        args += [image, "sh", "-lc", cmd]
    return args


def run_command(
    cmd: str,
    cwd: Path,
    timeout_sec: int,
    sandbox: Sandbox | None = None,
    argv: list[str] | None = None,
) -> CommandResult:
    start = time.time()

    if sandbox is not None and sandbox.backend == "container":
        container_argv = _build_container_command(cmd, cwd, sandbox, argv=argv)
        try:
            proc = subprocess.run(
                container_argv,
                shell=False,
                cwd=str(cwd),
                capture_output=True,
                text=True,
                timeout=timeout_sec,
                check=False,
            )
            duration = time.time() - start
            return CommandResult(
                cmd=cmd,
                exit_code=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                duration_sec=duration,
            )
        except subprocess.TimeoutExpired as exc:
            duration = time.time() - start
            stdout = (
                exc.stdout.decode("utf-8", errors="replace")
                if isinstance(exc.stdout, bytes)
                else (exc.stdout or "")
            )
            stderr = (
                exc.stderr.decode("utf-8", errors="replace")
                if isinstance(exc.stderr, bytes)
                else (exc.stderr or "")
            )
            stderr = f"{stderr}\n[veripatch] Container command timed out after {timeout_sec}s".strip()
            return CommandResult(
                cmd=cmd,
                exit_code=124,
                stdout=stdout,
                stderr=stderr,
                duration_sec=duration,
            )

    env = os.environ.copy()
    # Safety baseline for deterministic-ish CI-like behavior.
    env.setdefault("CI", "1")

    try:
        if argv:
            proc = subprocess.run(
                argv,
                shell=False,
                cwd=str(cwd),
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout_sec,
                check=False,
            )
        else:
            proc = subprocess.run(
                cmd,
                shell=True,
                cwd=str(cwd),
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout_sec,
                check=False,
            )
        duration = time.time() - start
        return CommandResult(
            cmd=cmd,
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            duration_sec=duration,
        )
    except subprocess.TimeoutExpired as exc:
        duration = time.time() - start
        stdout = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        stderr = f"{stderr}\n[veripatch] Command timed out after {timeout_sec}s".strip()
        return CommandResult(
            cmd=cmd,
            exit_code=124,
            stdout=stdout,
            stderr=stderr,
            duration_sec=duration,
        )
