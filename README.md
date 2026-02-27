# veripatch (MVP)

veripatch is a policy-governed proving engine.

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
- Proof bundles include source provenance (git metadata + workspace manifest).
- Patch application prefers `git apply` in git sandboxes with parser fallback.
- Local/OpenAI-compatible proposer retries empty or no-op diff responses and can fall back to single-file rewrite synthesis.

## Install

```bash
python -m pip install -e .
```

Optional YAML policy parsing:

```bash
python -m pip install -e .[yaml]
```

Development tooling:

```bash
python -m pip install -e .[dev]
ruff check .
mypy pp
python -m unittest discover -s tests -v
```

## Quick start

```bash
pp run "pytest -q"
```

Try the deterministic failing suite:

```bash
python examples/failing_targets/run_baseline.py
```

Then run one target with local model:

```bash
cd examples/failing_targets/name_error
pp run "python -m unittest discover -s tests -v" --policy pp.json --provider local --json
```

With explicit policy:

```bash
pp run "pytest -q" --policy pp.yaml
```

Run all configured proof targets:

```bash
pp prove --policy pp.yaml
```

Replay proof target:

```bash
pp replay .pp-artifacts/<session-id>/proof_bundle
```

`pp replay` now copies the source workspace to a temp sandbox, applies `final.patch`, and reruns the recorded proof target(s).

Replay against another local checkout:

```bash
pp replay .pp-artifacts/<session-id>/proof_bundle --cwd /path/to/repo
```

Replay + verify attestation:

```bash
pp replay .pp-artifacts/<session-id>/proof_bundle --verify-attestation
```

Machine-readable output:

```bash
pp run "pytest -q" --json
pp prove --policy pp.yaml --json
pp replay .pp-artifacts/<session-id>/proof_bundle --json
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

Use a local OpenAI-compatible model server (vLLM, LM Studio, llama.cpp server):

```bash
export PP_PROVIDER=local
export PP_LOCAL_BASE_URL=http://127.0.0.1:8000/v1
export PP_LOCAL_MODEL=Qwen/Qwen2.5-Coder-7B-Instruct
export PP_LOCAL_TIMEOUT_SEC=240
# optional if your local server enforces auth
export PP_LOCAL_API_KEY=...
pp run "pytest -q"
```

vLLM example for `Qwen/Qwen2.5-Coder-7B-Instruct`:

```bash
python -m vllm.entrypoints.openai.api_server \
  --model Qwen/Qwen2.5-Coder-7B-Instruct \
  --host 127.0.0.1 \
  --port 8000 \
  --dtype auto
```

Optional live smoke test (requires a running local model server):

```bash
PP_RUN_LOCAL_LM_SMOKE=1 python -m unittest tests.test_providers.ProviderTests.test_local_model_smoke -v
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
  allowed_argv:
    - ["pytest", "-q"]
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

Use `allowed_argv` for shellless command execution with exact argument matching.

## Output artifacts

Each run writes `.pp-artifacts/<session-id>/proof_bundle`:

- `repro.json`
- `policy.json`
- `environment.json`
- `workspace_manifest.json`
- `source_git.diff` (optional, if source repo was dirty)
- `attempts/<n>/...`
- `final.patch`
- `final_summary.md`
- `attestation.json` (optional)

`repro.json` also records portability metadata, including:

- `git_commit`, `git_branch`, `git_remote_url`, `git_dirty`
- `workspace_manifest_sha256`
- `container_runtime_version` (when available)

## Status

This is an MVP implementation focused on core architecture and verifiability.
