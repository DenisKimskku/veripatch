from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
from pathlib import Path
from typing import Any


@dataclass
class Limits:
    max_attempts: int = 3
    max_files_changed: int = 8
    max_patch_bytes: int = 200000
    per_command_timeout_sec: int = 600


@dataclass
class SandboxPolicy:
    backend: str = "auto"  # auto | copy | git_worktree | container
    container_runtime: str = "docker"
    container_image: str = "python:3.11-slim"
    container_workdir: str = "/workspace"
    cpu_limit: str | None = None
    memory_limit: str | None = None


@dataclass
class AttestationPolicy:
    enabled: bool = False
    mode: str = "none"  # none | hmac-sha256
    key_env: str = "PP_ATTEST_HMAC_KEY"


@dataclass
class Policy:
    network: str = "deny"
    allowed_commands: list[str] = field(default_factory=list)
    write_allowlist: list[str] = field(default_factory=lambda: ["**"])
    deny_write: list[str] = field(default_factory=list)
    limits: Limits = field(default_factory=Limits)
    minimize: bool = True
    sandbox: SandboxPolicy = field(default_factory=SandboxPolicy)
    attestation: AttestationPolicy = field(default_factory=AttestationPolicy)

    def is_command_allowed(self, cmd: str) -> bool:
        normalized = cmd.strip()
        return normalized in {c.strip() for c in self.allowed_commands}

    def policy_hash(self) -> str:
        raw = json.dumps(asdict(self), sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()


@dataclass
class ProofTarget:
    name: str
    cmd: str


@dataclass
class Config:
    proof_targets: list[ProofTarget]
    policy: Policy


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _load_mapping(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".json"}:
        return json.loads(text)

    try:
        import yaml  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "YAML policy requested but PyYAML is not installed. Install with: pip install -e .[yaml]"
        ) from exc
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError(f"Invalid config format in {path}")
    return data


def _build_config(mapping: dict[str, Any], fallback_cmd: str) -> Config:
    policy_raw = mapping.get("policy") or {}
    limits_raw = policy_raw.get("limits") or {}
    sandbox_raw = policy_raw.get("sandbox") or {}
    attestation_raw = policy_raw.get("attestation") or {}

    policy = Policy(
        network=policy_raw.get("network", "deny"),
        allowed_commands=_as_list(policy_raw.get("allowed_commands")),
        write_allowlist=_as_list(policy_raw.get("write_allowlist")) or ["**"],
        deny_write=_as_list(policy_raw.get("deny_write")),
        limits=Limits(
            max_attempts=int(limits_raw.get("max_attempts", 3)),
            max_files_changed=int(limits_raw.get("max_files_changed", 8)),
            max_patch_bytes=int(limits_raw.get("max_patch_bytes", 200000)),
            per_command_timeout_sec=int(limits_raw.get("per_command_timeout_sec", 600)),
        ),
        minimize=bool(policy_raw.get("minimize", True)),
        sandbox=SandboxPolicy(
            backend=str(sandbox_raw.get("backend", "auto")),
            container_runtime=str(sandbox_raw.get("container_runtime", "docker")),
            container_image=str(sandbox_raw.get("container_image", "python:3.11-slim")),
            container_workdir=str(sandbox_raw.get("container_workdir", "/workspace")),
            cpu_limit=(
                str(sandbox_raw["cpu_limit"]) if sandbox_raw.get("cpu_limit") is not None else None
            ),
            memory_limit=(
                str(sandbox_raw["memory_limit"]) if sandbox_raw.get("memory_limit") is not None else None
            ),
        ),
        attestation=AttestationPolicy(
            enabled=bool(attestation_raw.get("enabled", False)),
            mode=str(attestation_raw.get("mode", "none")),
            key_env=str(attestation_raw.get("key_env", "PP_ATTEST_HMAC_KEY")),
        ),
    )

    proof_targets_raw = mapping.get("proof_targets") or []
    targets: list[ProofTarget] = []
    for idx, item in enumerate(proof_targets_raw):
        if not isinstance(item, dict):
            continue
        cmd = str(item.get("cmd", "")).strip()
        if not cmd:
            continue
        name = str(item.get("name") or f"target-{idx + 1}")
        targets.append(ProofTarget(name=name, cmd=cmd))

    if not targets:
        targets = [ProofTarget(name="default", cmd=fallback_cmd)]

    if not policy.allowed_commands:
        policy.allowed_commands = [target.cmd for target in targets]

    if fallback_cmd not in policy.allowed_commands:
        policy.allowed_commands.append(fallback_cmd)

    return Config(proof_targets=targets, policy=policy)


def load_config(policy_path: str | None, fallback_cmd: str, workspace_root: Path) -> tuple[Config, Path | None]:
    path: Path | None = None
    if policy_path:
        path = Path(policy_path)
    else:
        for candidate in (workspace_root / "pp.yaml", workspace_root / "pp.yml", workspace_root / "pp.json"):
            if candidate.exists():
                path = candidate
                break

    if path is None:
        cfg = _build_config({}, fallback_cmd)
        return cfg, None

    data = _load_mapping(path)
    cfg = _build_config(data, fallback_cmd)
    return cfg, path


def config_to_dict(config: Config) -> dict[str, Any]:
    return {
        "proof_targets": [{"name": t.name, "cmd": t.cmd} for t in config.proof_targets],
        "policy": {
            "network": config.policy.network,
            "allowed_commands": config.policy.allowed_commands,
            "write_allowlist": config.policy.write_allowlist,
            "deny_write": config.policy.deny_write,
            "limits": {
                "max_attempts": config.policy.limits.max_attempts,
                "max_files_changed": config.policy.limits.max_files_changed,
                "max_patch_bytes": config.policy.limits.max_patch_bytes,
                "per_command_timeout_sec": config.policy.limits.per_command_timeout_sec,
            },
            "minimize": config.policy.minimize,
            "sandbox": {
                "backend": config.policy.sandbox.backend,
                "container_runtime": config.policy.sandbox.container_runtime,
                "container_image": config.policy.sandbox.container_image,
                "container_workdir": config.policy.sandbox.container_workdir,
                "cpu_limit": config.policy.sandbox.cpu_limit,
                "memory_limit": config.policy.sandbox.memory_limit,
            },
            "attestation": {
                "enabled": config.policy.attestation.enabled,
                "mode": config.policy.attestation.mode,
                "key_env": config.policy.attestation.key_env,
            },
        },
    }
