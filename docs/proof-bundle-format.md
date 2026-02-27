# Proof Bundle Format (MVP)

Directory shape:

```text
proof_bundle/
  repro.json
  policy.json
  environment.json
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

`attestation.json` contains:

- content hashes for all bundle files (excluding `attestation.json` itself),
- a bundle manifest digest,
- signing metadata (`none` or `hmac-sha256`),
- signature when signing is enabled.
