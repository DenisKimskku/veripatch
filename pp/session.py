from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import time
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

from .artifacts import ArtifactWriter
from .attest import create_attestation, verify_attestation
from .config import (
    Config,
    Policy,
    ProofTarget,
    config_to_dict,
    load_config,
    load_config_from_mapping,
)
from .context import extract_context
from .minimize import minimize_patch_hunks
from .models import AttemptRecord, ContextSlice, RunSummary
from .patch import (
    apply_patch_with_fallback,
    diff_between_dirs,
    patch_line_change_counts,
    patch_stats,
)
from .provenance import build_workspace_manifest, collect_git_metadata, manifest_sha256
from .providers import create_provider
from .providers.base import ProposalInput
from .redaction import redact_text
from .runner import Sandbox, cleanup_sandbox, create_sandbox, run_command


class SessionController:
    def __init__(self, workspace_root: Path) -> None:
        self.workspace_root = workspace_root.resolve()

    def _command_version(self, argv: list[str]) -> str | None:
        proc = subprocess.run(argv, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            return None
        out = (proc.stdout or proc.stderr).strip()
        return out or None

    def _redacted_context(self, ctx: ContextSlice) -> ContextSlice:
        return ContextSlice(
            locations=ctx.locations,
            snippets={k: redact_text(v) for k, v in ctx.snippets.items()},
            failing_assertions=[redact_text(a) for a in ctx.failing_assertions],
        )

    def _safe_target_name(self, name: str, index: int) -> str:
        raw = name.strip() or f"target{index}"
        sanitized = "".join(c if (c.isalnum() or c in {"-", "_"}) else "_" for c in raw)
        sanitized = sanitized.strip("_") or f"target{index}"
        return f"{index:02d}_{sanitized}"

    def _is_test_path(self, rel_path: str) -> bool:
        lowered = rel_path.lower()
        name = Path(rel_path).name.lower()
        return (
            lowered.startswith("tests/")
            or "/tests/" in f"/{lowered}"
            or name.startswith("test_")
            or name.endswith("_test.py")
        )

    def _collect_allowlisted_files(self, sandbox_root: Path, policy: Policy, max_files: int = 40) -> list[str]:
        files: list[str] = []
        for path in sorted(sandbox_root.rglob("*")):
            if not path.is_file():
                continue
            rel = path.relative_to(sandbox_root).as_posix()
            if rel.startswith(".git/") or rel.startswith(".pp-artifacts/"):
                continue
            if not any(fnmatch(rel, pattern) for pattern in policy.write_allowlist):
                continue
            if any(fnmatch(rel, pattern) for pattern in policy.deny_write):
                continue
            files.append(rel)
            if len(files) >= max_files:
                break
        return files

    def _extract_python_import_candidates(self, snippets: dict[str, str]) -> list[str]:
        module_paths: list[str] = []
        seen: set[str] = set()
        from_re = re.compile(r"^\s*from\s+([a-zA-Z_][\w\.]*)\s+import\s+", re.MULTILINE)
        import_re = re.compile(r"^\s*import\s+([a-zA-Z_][\w\.]*)", re.MULTILINE)

        for text in snippets.values():
            for match in from_re.finditer(text):
                module = match.group(1)
                candidate = f"{module.replace('.', '/')}.py"
                if candidate not in seen:
                    seen.add(candidate)
                    module_paths.append(candidate)
            for match in import_re.finditer(text):
                module = match.group(1).split(".", 1)[0]
                candidate = f"{module}.py"
                if candidate not in seen:
                    seen.add(candidate)
                    module_paths.append(candidate)

        return module_paths

    def _file_head_snippet(
        self,
        root: Path,
        rel_path: str,
        max_lines: int = 120,
        max_chars: int = 6000,
    ) -> str:
        target = root / rel_path
        if not target.exists() or not target.is_file():
            return ""

        text = target.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        out: list[str] = []
        for i, line in enumerate(lines[:max_lines], start=1):
            out.append(f"   {i:5d} | {line}")
        snippet = "\n".join(out)
        if len(lines) > max_lines:
            snippet += f"\n   ... ({len(lines) - max_lines} more lines)"
        return snippet[:max_chars]

    def _file_raw_snapshot(
        self,
        root: Path,
        rel_path: str,
        max_lines: int = 200,
        max_chars: int = 8000,
    ) -> str:
        target = root / rel_path
        if not target.exists() or not target.is_file():
            return ""

        text = target.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        snippet = "\n".join(lines[:max_lines])
        if len(lines) > max_lines:
            snippet += f"\n... ({len(lines) - max_lines} more lines)"
        return snippet[:max_chars]

    def _collect_editable_snapshots(
        self,
        sandbox_root: Path,
        policy: Policy,
        max_files: int = 8,
    ) -> dict[str, str]:
        snapshots: dict[str, str] = {}
        for rel_path in self._collect_allowlisted_files(sandbox_root, policy, max_files=max_files):
            raw = self._file_raw_snapshot(sandbox_root, rel_path)
            if not raw:
                continue
            snapshots[rel_path] = raw
        return snapshots

    def _augment_context_with_allowlist(
        self,
        context: ContextSlice,
        sandbox_root: Path,
        policy: Policy,
    ) -> ContextSlice:
        snippets = dict(context.snippets)
        existing_files = {key.split(":", 1)[0] for key in snippets}
        has_non_test_context = any(not self._is_test_path(path) for path in existing_files)
        if has_non_test_context:
            return context

        allowlisted = self._collect_allowlisted_files(sandbox_root, policy)
        candidates = [path for path in allowlisted if not self._is_test_path(path) and path not in existing_files]
        if not candidates:
            return context

        imports = self._extract_python_import_candidates(snippets)
        prioritized: list[str] = []
        seen: set[str] = set()
        for module_path in imports:
            for path in candidates:
                if path == module_path or path.endswith(f"/{module_path}"):
                    if path not in seen:
                        seen.add(path)
                        prioritized.append(path)

        for path in candidates:
            if path not in seen:
                seen.add(path)
                prioritized.append(path)

        for path in prioritized[:4]:
            snippet = self._file_head_snippet(sandbox_root, path)
            if snippet:
                snippets[f"{path}:1"] = snippet

        return ContextSlice(
            locations=context.locations,
            snippets=snippets,
            failing_assertions=context.failing_assertions,
        )

    def _extract_paths_from_diff(self, diff_text: str) -> list[str]:
        paths: list[str] = []
        seen: set[str] = set()
        for line in diff_text.splitlines():
            if not line.startswith("+++ "):
                continue
            raw = line[4:].strip().split("\t", 1)[0]
            if raw == "/dev/null":
                continue
            rel = raw[2:] if raw.startswith(("a/", "b/")) else raw
            rel = rel.strip()
            if not rel or rel in seen:
                continue
            seen.add(rel)
            paths.append(rel)
        return paths

    def _patch_rejection_feedback(self, err: str, diff_text: str, sandbox_root: Path) -> str:
        paths = self._extract_paths_from_diff(diff_text)
        if not paths:
            return err

        chunks: list[str] = [
            err,
            (
                "RETRY_INSTRUCTION: Build the next diff from the exact file snapshots below. "
                "Use '-' lines that exist verbatim and '+' lines for replacements. "
                "If hunk matching is hard, rewrite the whole file in one hunk from line 1."
            ),
            "Current file snapshots:",
        ]
        for rel_path in paths[:2]:
            snippet = self._file_head_snippet(sandbox_root, rel_path, max_lines=60, max_chars=2500)
            if snippet:
                chunks.append(f"### {rel_path}\n{snippet}")
        return "\n".join(chunks)[:5000]

    def _run_targets(
        self,
        targets: list[ProofTarget],
        sandbox: Sandbox | None,
        timeout_sec: int,
        policy: Policy | None = None,
        cwd: Path | None = None,
        artifacts: ArtifactWriter | None = None,
        artifact_rel_prefix: str | None = None,
    ) -> tuple[bool, Any, str, list[dict[str, Any]]]:
        if not targets:
            raise RuntimeError("No proof targets configured")

        first_failure = None
        first_failure_cmd = ""
        last_result = None
        last_cmd = ""
        rows: list[dict[str, Any]] = []

        work_cwd = cwd or (sandbox.root if sandbox else self.workspace_root)

        for idx, target in enumerate(targets, start=1):
            cmd_argv: list[str] | None = None
            if policy is not None:
                allowed, cmd_argv = policy.command_execution(target.cmd)
                if not allowed:
                    raise RuntimeError(f"Command is not allowed by policy: {target.cmd}")
            result = run_command(target.cmd, work_cwd, timeout_sec, sandbox=sandbox, argv=cmd_argv)
            last_result = result
            last_cmd = target.cmd

            row = {
                "name": target.name,
                "cmd": target.cmd,
                "exit_code": result.exit_code,
                "duration_sec": result.duration_sec,
            }
            rows.append(row)

            if artifacts and artifact_rel_prefix:
                artifacts.write_command_result(
                    f"{artifact_rel_prefix}/{self._safe_target_name(target.name, idx)}.json",
                    result,
                )

            if first_failure is None and result.exit_code != 0:
                first_failure = result
                first_failure_cmd = target.cmd

        if artifacts and artifact_rel_prefix:
            artifacts.write_json(f"{artifact_rel_prefix}/target_results.json", rows)
            if len(targets) == 1 and last_result is not None:
                artifacts.write_command_result(f"{artifact_rel_prefix}/verify.json", last_result)

        representative = first_failure or last_result
        representative_cmd = first_failure_cmd or last_cmd
        return first_failure is None, representative, representative_cmd, rows

    def _combined_verify_command(self, targets: list[ProofTarget]) -> str:
        if len(targets) == 1:
            return targets[0].cmd
        return " && ".join(f"({t.cmd})" for t in targets)

    def _execute_session(
        self,
        config: Config,
        resolved_policy_path: Path | None,
        provider_name: str | None,
        keep_sandbox: bool,
        attest: bool,
        attestation_mode: str | None,
        attestation_key_env: str | None,
    ) -> RunSummary:
        started_at = time.time()
        policy = config.policy

        if not config.proof_targets:
            raise RuntimeError("No proof targets configured")

        for target in config.proof_targets:
            if not policy.is_command_allowed(target.cmd):
                raise RuntimeError(
                    f"Command is not allowed by policy: {target.cmd}. Allowed: {policy.allowed_commands}"
                )

        provider = create_provider(provider_name)
        active_provider = provider.__class__.__name__
        artifacts = ArtifactWriter(self.workspace_root)

        sandbox = create_sandbox(self.workspace_root, policy)
        artifacts.write_environment(
            sandbox.backend,
            extra={
                "workspace_backend": sandbox.workspace_backend,
                "network_policy": policy.network,
                "container_runtime": sandbox.container_runtime,
                "container_image": sandbox.container_image,
                "container_image_id": sandbox.container_image_id,
                "container_workdir": sandbox.container_workdir,
                "cpu_limit": sandbox.cpu_limit,
                "memory_limit": sandbox.memory_limit,
            },
        )
        artifacts.write_policy(config_to_dict(config))

        manifest_files = build_workspace_manifest(self.workspace_root)
        manifest_digest = manifest_sha256(manifest_files)
        artifacts.write_json("workspace_manifest.json", {"files": manifest_files})

        git_meta = collect_git_metadata(self.workspace_root)
        source_git_diff_path: str | None = None
        if isinstance(git_meta.get("git_diff"), str) and git_meta["git_diff"]:
            path = artifacts.write_text("source_git.diff", git_meta["git_diff"])
            source_git_diff_path = path.name

        container_runtime_version = None
        if sandbox.container_runtime:
            container_runtime_version = self._command_version([sandbox.container_runtime, "--version"])

        repro: dict[str, Any] = {
            "command": self._combined_verify_command(config.proof_targets),
            "workspace_root": str(self.workspace_root),
            "policy_path": str(resolved_policy_path) if resolved_policy_path else None,
            "policy_hash": policy.policy_hash(),
            "provider": active_provider,
            "started_at_unix": started_at,
            "sandbox_backend": sandbox.backend,
            "workspace_backend": sandbox.workspace_backend,
            "network_policy": policy.network,
            "container_runtime": sandbox.container_runtime,
            "container_image": sandbox.container_image,
            "container_image_id": sandbox.container_image_id,
            "container_workdir": sandbox.container_workdir,
            "cpu_limit": sandbox.cpu_limit,
            "memory_limit": sandbox.memory_limit,
            "container_runtime_version": container_runtime_version,
            "proof_targets": [{"name": t.name, "cmd": t.cmd} for t in config.proof_targets],
            "is_git_repo": git_meta.get("is_git_repo"),
            "git_commit": git_meta.get("git_commit"),
            "git_branch": git_meta.get("git_branch"),
            "git_remote_url": git_meta.get("git_remote_url"),
            "git_dirty": git_meta.get("git_dirty"),
            "workspace_manifest_path": "workspace_manifest.json",
            "workspace_manifest_sha256": manifest_digest,
            "source_git_diff_path": source_git_diff_path,
        }

        attempt_records: list[AttemptRecord] = []
        max_attempts = policy.limits.max_attempts
        timeout = policy.limits.per_command_timeout_sec
        previous_errors: list[str] = []
        previous_diffs: set[str] = set()

        baseline_ok, baseline_result, failing_cmd, _ = self._run_targets(
            config.proof_targets,
            sandbox,
            timeout,
            policy=policy,
            artifacts=artifacts,
            artifact_rel_prefix="attempts/0_baseline",
        )
        final_result = baseline_result
        active_failure_cmd = failing_cmd
        success = baseline_ok

        if not success:
            for attempt_no in range(1, max_attempts + 1):
                context = extract_context(
                    final_result.combined_output,
                    sandbox.root,
                    container_workdir=sandbox.container_workdir if sandbox.backend == "container" else None,
                )
                context = self._augment_context_with_allowlist(context, sandbox.root, policy)
                sanitized = redact_text(final_result.combined_output)
                redacted_context = self._redacted_context(context)
                editable_files = self._collect_editable_snapshots(sandbox.root, policy)

                proposal_input = ProposalInput(
                    command=active_failure_cmd,
                    failure_output=sanitized,
                    context=redacted_context,
                    previous_attempts=previous_errors,
                    write_allowlist=policy.write_allowlist,
                    deny_write=policy.deny_write,
                    editable_files=editable_files,
                )

                try:
                    proposal = provider.propose(proposal_input)
                except Exception as exc:
                    err = f"Provider error: {exc}"
                    attempt_records.append(
                        AttemptRecord(
                            number=attempt_no,
                            proposed=None,
                            apply_ok=False,
                            verify_result=None,
                            error=err,
                        )
                    )
                    artifacts.write_text(f"attempts/{attempt_no}/error.txt", err)
                    previous_errors.append(err)
                    continue

                artifacts.write_proposal(attempt_no, proposal)
                artifacts.write_text(f"attempts/{attempt_no}/applied.patch", proposal.diff)

                if not proposal.diff.strip():
                    err = (
                        "Provider returned empty diff while proof target is still failing. "
                        "Return a best-effort patch against allowlisted files."
                    )
                    attempt_records.append(
                        AttemptRecord(
                            number=attempt_no,
                            proposed=proposal,
                            apply_ok=False,
                            verify_result=None,
                            error=err,
                        )
                    )
                    artifacts.write_text(f"attempts/{attempt_no}/error.txt", err)
                    previous_errors.append(err)
                    continue

                if proposal.diff in previous_diffs:
                    err = self._patch_rejection_feedback(
                        "Patch apply rejected: Provider repeated an identical diff from a prior attempt.",
                        proposal.diff,
                        sandbox.root,
                    )
                    attempt_records.append(
                        AttemptRecord(
                            number=attempt_no,
                            proposed=proposal,
                            apply_ok=False,
                            verify_result=None,
                            error=err,
                        )
                    )
                    artifacts.write_text(f"attempts/{attempt_no}/error.txt", err)
                    previous_errors.append(err)
                    continue

                previous_diffs.add(proposal.diff)

                try:
                    file_count, patch_bytes = patch_stats(proposal.diff)
                    additions, deletions = patch_line_change_counts(proposal.diff)
                    artifacts.write_json(
                        f"attempts/{attempt_no}/patch_stats.json",
                        {
                            "files": file_count,
                            "bytes": patch_bytes,
                            "additions": additions,
                            "deletions": deletions,
                        },
                    )
                    if additions + deletions == 0:
                        raise ValueError("Patch contains no line-level edits")
                    changed_paths = apply_patch_with_fallback(proposal.diff, sandbox.root, policy)
                    artifacts.write_json(f"attempts/{attempt_no}/changed_paths.json", changed_paths)
                except Exception as exc:
                    err = self._patch_rejection_feedback(
                        f"Patch apply rejected: {exc}",
                        proposal.diff,
                        sandbox.root,
                    )
                    attempt_records.append(
                        AttemptRecord(
                            number=attempt_no,
                            proposed=proposal,
                            apply_ok=False,
                            verify_result=None,
                            error=err,
                        )
                    )
                    artifacts.write_text(f"attempts/{attempt_no}/error.txt", err)
                    previous_errors.append(err)
                    continue

                verify_ok, verify_result, failing_cmd, _ = self._run_targets(
                    config.proof_targets,
                    sandbox,
                    timeout,
                    policy=policy,
                    artifacts=artifacts,
                    artifact_rel_prefix=f"attempts/{attempt_no}/verify",
                )

                attempt_records.append(
                    AttemptRecord(
                        number=attempt_no,
                        proposed=proposal,
                        apply_ok=True,
                        verify_result=verify_result,
                        error=None,
                    )
                )

                final_result = verify_result
                if verify_ok:
                    success = True
                    break

                active_failure_cmd = failing_cmd
                previous_errors.append(
                    f"attempt {attempt_no} verify failed for `{failing_cmd}` with exit code {verify_result.exit_code}"
                )

        final_patch = diff_between_dirs(self.workspace_root, sandbox.root)

        if success and final_patch.strip() and policy.minimize:
            minimized = minimize_patch_hunks(
                patch_text=final_patch,
                baseline_root=self.workspace_root,
                verify_cmd=self._combined_verify_command(config.proof_targets),
                timeout_sec=timeout,
                policy=policy,
                execution_sandbox=sandbox,
            )
            if minimized.strip():
                final_patch = minimized

        final_patch_path = artifacts.write_text("final.patch", final_patch)

        summary_lines = [
            "# veripatch Summary",
            "",
            f"- success: {str(success).lower()}",
            f"- proof_target_count: {len(config.proof_targets)}",
            f"- verify_command: `{self._combined_verify_command(config.proof_targets)}`",
            f"- attempts_used: {len(attempt_records)}",
            f"- final_exit_code: {final_result.exit_code}",
            f"- policy_hash: `{policy.policy_hash()}`",
            "",
            "## Final result",
            "",
            "```text",
            (final_result.stdout or "")[:4000],
            (final_result.stderr or "")[:4000],
            "```",
        ]
        should_attest = attest or policy.attestation.enabled
        resolved_mode = (attestation_mode or policy.attestation.mode or "none").strip().lower()
        resolved_key_env = (attestation_key_env or policy.attestation.key_env or "PP_ATTEST_HMAC_KEY").strip()
        if should_attest:
            summary_lines.insert(8, f"- attestation_mode: `{resolved_mode}`")
        artifacts.write_summary("\n".join(summary_lines))

        repro.update(
            {
                "finished_at_unix": time.time(),
                "success": success,
                "attempts_used": len(attempt_records),
                "final_exit_code": final_result.exit_code,
                "artifact_dir": str(artifacts.proof_bundle_dir),
            }
        )
        artifacts.write_repro(repro)
        attestation_path: Path | None = None
        if should_attest:
            attestation_path = create_attestation(
                artifacts.proof_bundle_dir,
                mode=resolved_mode,
                key_env=resolved_key_env,
            )

        if not keep_sandbox:
            cleanup_sandbox(sandbox)
        else:
            artifacts.write_text("sandbox_path.txt", str(sandbox.root))

        return RunSummary(
            success=success,
            attempts_used=len(attempt_records),
            final_patch_path=final_patch_path,
            proof_bundle_dir=artifacts.proof_bundle_dir,
            final_result=final_result,
            attempt_records=attempt_records,
            extra={
                "session_dir": str(artifacts.session_dir),
                "repro": repro,
                "attestation_path": str(attestation_path) if attestation_path else None,
            },
        )

    def run(
        self,
        command: str,
        policy_path: str | None = None,
        provider_name: str | None = None,
        keep_sandbox: bool = False,
        attest: bool = False,
        attestation_mode: str | None = None,
        attestation_key_env: str | None = None,
    ) -> RunSummary:
        loaded, resolved_policy_path = load_config(policy_path, command, self.workspace_root)
        config = Config(
            proof_targets=[ProofTarget(name="default", cmd=command)],
            policy=loaded.policy,
        )
        return self._execute_session(
            config=config,
            resolved_policy_path=resolved_policy_path,
            provider_name=provider_name,
            keep_sandbox=keep_sandbox,
            attest=attest,
            attestation_mode=attestation_mode,
            attestation_key_env=attestation_key_env,
        )

    def prove(
        self,
        policy_path: str | None = None,
        provider_name: str | None = None,
        keep_sandbox: bool = False,
        attest: bool = False,
        attestation_mode: str | None = None,
        attestation_key_env: str | None = None,
    ) -> RunSummary:
        config, resolved_policy_path = load_config(policy_path, "true", self.workspace_root)
        if not config.proof_targets:
            raise RuntimeError("No proof targets configured. Add proof_targets in policy file.")
        return self._execute_session(
            config=config,
            resolved_policy_path=resolved_policy_path,
            provider_name=provider_name,
            keep_sandbox=keep_sandbox,
            attest=attest,
            attestation_mode=attestation_mode,
            attestation_key_env=attestation_key_env,
        )

    def replay(
        self,
        bundle_dir: Path,
        cwd_override: Path | None = None,
        verify_bundle_attestation: bool = False,
    ) -> dict[str, Any]:
        repro_path = bundle_dir / "repro.json"
        if not repro_path.exists():
            raise RuntimeError(f"Missing repro.json in {bundle_dir}")

        repro = json.loads(repro_path.read_text(encoding="utf-8"))
        fallback_command = str(repro.get("command") or "").strip()
        if not fallback_command and not repro.get("proof_targets"):
            raise RuntimeError("repro.json does not include command/proof_targets")

        targets: list[ProofTarget] = []
        for idx, item in enumerate(repro.get("proof_targets") or []):
            if not isinstance(item, dict):
                continue
            cmd = str(item.get("cmd") or "").strip()
            if not cmd:
                continue
            name = str(item.get("name") or f"target-{idx + 1}")
            targets.append(ProofTarget(name=name, cmd=cmd))

        if not targets:
            targets = [ProofTarget(name="default", cmd=fallback_command)]

        source_root = cwd_override or Path(str(repro.get("workspace_root") or self.workspace_root))
        source_root = source_root.resolve()
        if not source_root.exists() or not source_root.is_dir():
            raise RuntimeError(f"Replay source root does not exist: {source_root}")

        temp_parent = Path(tempfile.mkdtemp(prefix="pp-replay-"))
        replay_root = temp_parent / "workspace"
        shutil.copytree(
            source_root,
            replay_root,
            ignore=shutil.ignore_patterns(".pp-artifacts", "__pycache__", ".pytest_cache"),
        )

        try:
            timeout_sec = 600
            policy = Policy(allowed_commands=[t.cmd for t in targets])

            policy_path = bundle_dir / "policy.json"
            if policy_path.exists():
                policy_mapping = json.loads(policy_path.read_text(encoding="utf-8"))
                loaded = load_config_from_mapping(policy_mapping, targets[0].cmd)
                policy = loaded.policy
                timeout_sec = policy.limits.per_command_timeout_sec

            final_patch_path = bundle_dir / "final.patch"
            if final_patch_path.exists():
                patch_text = final_patch_path.read_text(encoding="utf-8")
                if patch_text.strip():
                    apply_patch_with_fallback(patch_text, replay_root, policy)

            replay_sandbox: Sandbox | None = None
            if policy.sandbox.backend.strip().lower() == "container":
                replay_sandbox = Sandbox(
                    root=replay_root,
                    backend="container",
                    workspace_backend="copy",
                    control_root=replay_root,
                    cleanup_token=None,
                    container_runtime=policy.sandbox.container_runtime,
                    container_image=policy.sandbox.container_image,
                    container_workdir=policy.sandbox.container_workdir,
                    network=policy.network,
                    cpu_limit=policy.sandbox.cpu_limit,
                    memory_limit=policy.sandbox.memory_limit,
                )

            ok, representative, _, target_rows = self._run_targets(
                targets,
                replay_sandbox,
                timeout_sec,
                policy=policy,
                cwd=replay_root,
                artifacts=None,
                artifact_rel_prefix=None,
            )

            payload = {
                "command": self._combined_verify_command(targets),
                "cwd": str(source_root),
                "replay_root": str(replay_root),
                "exit_code": representative.exit_code,
                "duration_sec": representative.duration_sec,
                "stdout": representative.stdout,
                "stderr": representative.stderr,
                "success": ok,
                "sandbox_backend": replay_sandbox.backend if replay_sandbox else "native",
                "target_results": target_rows,
            }
            if verify_bundle_attestation:
                payload["attestation"] = verify_attestation(bundle_dir)
            return payload
        finally:
            shutil.rmtree(temp_parent, ignore_errors=True)
