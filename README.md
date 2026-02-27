# Patch & Prove (MVP)

Patch & Prove is a policy-governed proving engine.

Given a failing command, it iterates in a sandbox:

1. run and capture evidence,
2. extract minimal context,
3. ask a patch proposer for a unified diff,
4. apply under policy constraints,
5. rerun verification,
6. emit proof artifacts (+ optional attestation).

## Why this repo

- Deterministic systems judge success (`tests/build/typecheck`).
- LLM output is bounded to diffs.
- Policy enforces command and file boundaries.
- Optional container execution supports no-network runs.
- Every run emits replayable artifacts.

## Install

```bash
python -m pip install -e .
```

Optional YAML policy parsing:

```bash
python -m pip install -e .[yaml]
```

## Quick start

```bash
pp run "pytest -q"
```

With explicit policy:

```bash
pp run "pytest -q" --policy pp.yaml
```

Replay proof target:

```bash
pp replay .pp-artifacts/<session-id>/proof_bundle
```

Replay + verify attestation:

```bash
pp replay .pp-artifacts/<session-id>/proof_bundle --verify-attestation
```

## Provider configuration

Default provider is `stub` (returns no-op patch).

Use an OpenAI-compatible endpoint:

```bash
export PP_PROVIDER=openai
export PP_OPENAI_API_KEY=...
export PP_OPENAI_BASE_URL=https://api.openai.com/v1
export PP_OPENAI_MODEL=gpt-4.1-mini
export PP_OPENAI_MAX_TOKENS=2000
pp run "pytest -q"
```

## Attestation commands

Create/overwrite an attestation for an existing bundle:

```bash
pp attest .pp-artifacts/<session-id>/proof_bundle --mode hmac-sha256 --key-env PP_ATTEST_HMAC_KEY
```

Verify a bundle attestation:

```bash
pp verify-attestation .pp-artifacts/<session-id>/proof_bundle
```

## Policy (`pp.yaml`)

```yaml
proof_targets:
  - name: unit
    cmd: "pytest -q"
policy:
  network: deny
  allowed_commands:
    - "pytest -q"
  write_allowlist:
    - "src/**"
    - "tests/**"
  deny_write:
    - "**/.env"
    - "**/secrets/**"
  limits:
    max_attempts: 3
    max_files_changed: 8
    max_patch_bytes: 200000
    per_command_timeout_sec: 600
  minimize: true
  sandbox:
    backend: container
    container_runtime: docker
    container_image: python:3.11-slim
    container_workdir: /workspace
    cpu_limit: "2"
    memory_limit: "2g"
  attestation:
    enabled: true
    mode: hmac-sha256
    key_env: PP_ATTEST_HMAC_KEY
```

## Output artifacts

Each run writes `.pp-artifacts/<session-id>/proof_bundle`:

- `repro.json`
- `policy.json`
- `environment.json`
- `attempts/<n>/...`
- `final.patch`
- `final_summary.md`
- `attestation.json` (optional)

## Status

This is an MVP implementation focused on core architecture and verifiability.
