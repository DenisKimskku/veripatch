# Threat Model (MVP)

## In scope

- Accidental edits outside intended source tree.
- Overly broad patches.
- Secret leakage in outbound model context.
- Unbounded retry loops.
- Tampering of proof-bundle artifacts after run.

## Mitigations

- Path allowlist/denylist on patch apply.
- Limits for attempts, files changed, patch bytes, command timeout.
- Deterministic redaction before provider calls.
- Optional container runtime with `--network none` and resource limits.
- Replayable artifacts with policy hash and command logs.
- Optional bundle attestation (`hmac-sha256`) for integrity checks.

## Not yet fully covered

- Full seccomp/apparmor hardening.
- Prompt-injection complete containment.
- Asymmetric signing (Sigstore/minisign/cosign).
