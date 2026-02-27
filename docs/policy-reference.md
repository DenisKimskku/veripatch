# Policy Reference (MVP)

Top-level config fields:

- `proof_targets[]`: named command list.
- `policy.network`: `deny` or `allow`.
- `policy.allowed_commands[]`: exact command strings permitted.
- `policy.write_allowlist[]`: glob patterns allowed for patch writes.
- `policy.deny_write[]`: glob patterns denied even if allowlisted.
- `policy.limits.max_attempts`
- `policy.limits.max_files_changed`
- `policy.limits.max_patch_bytes`
- `policy.limits.per_command_timeout_sec`
- `policy.minimize`: enable hunk-level patch minimization after passing verification.

Sandbox controls:

- `policy.sandbox.backend`: `auto`, `copy`, `git_worktree`, or `container`.
- `policy.sandbox.container_runtime`: default `docker`.
- `policy.sandbox.container_image`: container image used when backend is `container`.
- `policy.sandbox.container_workdir`: mount target path inside container (`/workspace` default).
- `policy.sandbox.cpu_limit`: optional runtime `--cpus` value.
- `policy.sandbox.memory_limit`: optional runtime `--memory` value.

When `policy.sandbox.backend=container` and `policy.network=deny`, commands run with `--network none`.

Attestation controls:

- `policy.attestation.enabled`: emit `attestation.json` after run.
- `policy.attestation.mode`: `none` or `hmac-sha256`.
- `policy.attestation.key_env`: environment variable carrying the HMAC key.

Default behavior without policy file:

- allow exactly the `pp run` command.
- allow writes to `**`.
- 3 attempts, 8 max files changed, 200000 max patch bytes, 600s command timeout.
- sandbox backend `auto` (git worktree when in git repo, else copy).
- attestation disabled.
