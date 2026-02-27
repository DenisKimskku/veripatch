from __future__ import annotations

from pathlib import Path
import time
from typing import Any

from .attest import create_attestation, verify_attestation
from .artifacts import ArtifactWriter
from .config import config_to_dict, load_config
from .context import extract_context
from .minimize import minimize_patch_hunks
from .models import AttemptRecord, ContextSlice, RunSummary
from .patch import apply_unified_diff, diff_between_dirs, patch_stats
from .providers import create_provider
from .providers.base import ProposalInput
from .redaction import redact_text
from .runner import Sandbox, cleanup_sandbox, create_sandbox, run_command


class SessionController:
    def __init__(self, workspace_root: Path) -> None:
        self.workspace_root = workspace_root.resolve()

    def _redacted_context(self, ctx: ContextSlice) -> ContextSlice:
        return ContextSlice(
            locations=ctx.locations,
            snippets={k: redact_text(v) for k, v in ctx.snippets.items()},
            failing_assertions=[redact_text(a) for a in ctx.failing_assertions],
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
        started_at = time.time()
        config, resolved_policy_path = load_config(policy_path, command, self.workspace_root)
        policy = config.policy

        if not policy.is_command_allowed(command):
            raise RuntimeError(
                f"Command is not allowed by policy: {command}. Allowed: {policy.allowed_commands}"
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

        repro: dict[str, Any] = {
            "command": command,
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
        }

        attempt_records: list[AttemptRecord] = []
        max_attempts = policy.limits.max_attempts
        timeout = policy.limits.per_command_timeout_sec
        previous_errors: list[str] = []

        baseline = run_command(command, sandbox.root, timeout, sandbox=sandbox)
        artifacts.write_command_result("attempts/0_baseline/verify.json", baseline)
        final_result = baseline
        success = baseline.exit_code == 0

        if not success:
            for attempt_no in range(1, max_attempts + 1):
                context = extract_context(final_result.combined_output, sandbox.root)
                sanitized = redact_text(final_result.combined_output)
                redacted_context = self._redacted_context(context)

                proposal_input = ProposalInput(
                    command=command,
                    failure_output=sanitized,
                    context=redacted_context,
                    previous_attempts=previous_errors,
                    write_allowlist=policy.write_allowlist,
                    deny_write=policy.deny_write,
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
                    err = "Provider returned empty diff"
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
                    break

                try:
                    file_count, patch_bytes = patch_stats(proposal.diff)
                    artifacts.write_json(
                        f"attempts/{attempt_no}/patch_stats.json",
                        {
                            "files": file_count,
                            "bytes": patch_bytes,
                        },
                    )
                    changed_paths = apply_unified_diff(proposal.diff, sandbox.root, policy)
                    artifacts.write_json(f"attempts/{attempt_no}/changed_paths.json", changed_paths)
                except Exception as exc:
                    err = f"Patch apply rejected: {exc}"
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

                verify_result = run_command(command, sandbox.root, timeout, sandbox=sandbox)
                artifacts.write_command_result(f"attempts/{attempt_no}/verify.json", verify_result)

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
                if verify_result.exit_code == 0:
                    success = True
                    break

                previous_errors.append(
                    f"attempt {attempt_no} verify failed with exit code {verify_result.exit_code}"
                )

        final_patch = diff_between_dirs(self.workspace_root, sandbox.root)

        if success and final_patch.strip() and policy.minimize:
            minimized = minimize_patch_hunks(
                patch_text=final_patch,
                baseline_root=self.workspace_root,
                verify_cmd=command,
                timeout_sec=timeout,
                policy=policy,
                execution_sandbox=sandbox,
            )
            if minimized.strip():
                final_patch = minimized

        final_patch_path = artifacts.write_text("final.patch", final_patch)

        summary_lines = [
            "# Patch & Prove Summary",
            "",
            f"- success: {str(success).lower()}",
            f"- command: `{command}`",
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
            summary_lines.insert(7, f"- attestation_mode: `{resolved_mode}`")
        artifacts.write_summary("\n".join(summary_lines))

        repro.update(
            {
                "finished_at_unix": time.time(),
                "success": success,
                "attempts_used": len(attempt_records),
                "final_exit_code": final_result.exit_code,
                "proof_targets": [{"name": t.name, "cmd": t.cmd} for t in config.proof_targets],
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

    def replay(
        self,
        bundle_dir: Path,
        cwd_override: Path | None = None,
        verify_bundle_attestation: bool = False,
    ) -> dict[str, Any]:
        repro_path = bundle_dir / "repro.json"
        if not repro_path.exists():
            raise RuntimeError(f"Missing repro.json in {bundle_dir}")

        import json

        repro = json.loads(repro_path.read_text(encoding="utf-8"))
        command = repro.get("command")
        if not command:
            raise RuntimeError("repro.json does not include a command")

        cwd = cwd_override or Path(str(repro.get("workspace_root") or self.workspace_root))
        timeout_sec = 600
        replay_sandbox: Sandbox | None = None

        policy_path = bundle_dir / "policy.json"
        if policy_path.exists():
            policy_data = json.loads(policy_path.read_text(encoding="utf-8"))
            timeout_sec = int(
                policy_data.get("policy", {})
                .get("limits", {})
                .get("per_command_timeout_sec", timeout_sec)
            )
            sandbox_data = policy_data.get("policy", {}).get("sandbox", {}) or {}
            network = str(policy_data.get("policy", {}).get("network", "deny"))
            backend = str(sandbox_data.get("backend", "auto")).strip().lower()
            if backend == "container":
                replay_sandbox = Sandbox(
                    root=cwd,
                    backend="container",
                    workspace_backend="copy",
                    control_root=cwd,
                    cleanup_token=None,
                    container_runtime=str(sandbox_data.get("container_runtime", "docker")),
                    container_image=str(sandbox_data.get("container_image", "python:3.11-slim")),
                    container_workdir=str(sandbox_data.get("container_workdir", "/workspace")),
                    network=network,
                    cpu_limit=(
                        str(sandbox_data["cpu_limit"]) if sandbox_data.get("cpu_limit") is not None else None
                    ),
                    memory_limit=(
                        str(sandbox_data["memory_limit"]) if sandbox_data.get("memory_limit") is not None else None
                    ),
                )

        result = run_command(command, cwd, timeout_sec, sandbox=replay_sandbox)
        payload = {
            "command": command,
            "cwd": str(cwd),
            "exit_code": result.exit_code,
            "duration_sec": result.duration_sec,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "success": result.exit_code == 0,
            "sandbox_backend": replay_sandbox.backend if replay_sandbox else "native",
        }
        if verify_bundle_attestation:
            payload["attestation"] = verify_attestation(bundle_dir)
        return payload
