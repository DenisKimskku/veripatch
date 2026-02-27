# Proof Bundle Format (MVP)

Directory shape:

```text
proof_bundle/
  repro.json
  policy.json
  environment.json
  workspace_manifest.json
  source_git.diff     # optional, when source repo was dirty
  attempts/
    0_baseline/verify.json
    N/proposed.json
    N/applied.patch
    N/verify.json
  final.patch
  final_summary.md
  attestation.json   # optional
```

`repro.json` includes command, policy hash, workspace root, provider, timing, backend, and result.
It also includes portability metadata such as git commit/dirty status/remote URL and manifest digest.

`attestation.json` contains:

- content hashes for all bundle files (excluding `attestation.json` itself),
- a bundle manifest digest,
- signing metadata (`none` or `hmac-sha256`),
- signature when signing is enabled.
