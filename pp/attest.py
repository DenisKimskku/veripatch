from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from typing import Any

_ATTESTATION_FILENAME = "attestation.json"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _iter_bundle_files(bundle_dir: Path) -> list[Path]:
    files: list[Path] = []
    for path in bundle_dir.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(bundle_dir).as_posix()
        if rel == _ATTESTATION_FILENAME:
            continue
        files.append(path)
    return sorted(files)


def _statement_for_bundle(bundle_dir: Path) -> dict[str, Any]:
    files: dict[str, dict[str, Any]] = {}
    for path in _iter_bundle_files(bundle_dir):
        rel = path.relative_to(bundle_dir).as_posix()
        raw = path.read_bytes()
        files[rel] = {
            "sha256": _sha256_bytes(raw),
            "bytes": len(raw),
        }

    manifest_hash = _sha256_bytes(_canonical_json_bytes({"files": files}))
    return {
        "version": "pp-attestation-statement/v1",
        "bundle_manifest_sha256": manifest_hash,
        "files": files,
    }


def create_attestation(bundle_dir: Path, mode: str = "none", key_env: str = "PP_ATTEST_HMAC_KEY") -> Path:
    mode_norm = mode.strip().lower()
    if mode_norm not in {"none", "hmac-sha256"}:
        raise RuntimeError(f"Unsupported attestation mode: {mode}")

    statement = _statement_for_bundle(bundle_dir)
    signing: dict[str, Any] = {
        "mode": mode_norm,
        "key_env": key_env,
    }

    if mode_norm == "hmac-sha256":
        key = os.getenv(key_env)
        if not key:
            raise RuntimeError(
                f"Attestation mode hmac-sha256 requires environment variable {key_env}"
            )
        sig = hmac.new(key.encode("utf-8"), _canonical_json_bytes(statement), hashlib.sha256).hexdigest()
        signing["signature"] = sig
        signing["key_id"] = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]

    attestation = {
        "version": "pp-attestation/v1",
        "created_at_unix": time.time(),
        "statement": statement,
        "signing": signing,
    }

    target = bundle_dir / _ATTESTATION_FILENAME
    target.write_text(json.dumps(attestation, indent=2, sort_keys=True), encoding="utf-8")
    return target


def verify_attestation(bundle_dir: Path) -> dict[str, Any]:
    path = bundle_dir / _ATTESTATION_FILENAME
    if not path.exists():
        return {
            "ok": False,
            "error": f"Missing {path}",
            "signature_valid": False,
            "content_valid": False,
        }

    attestation = json.loads(path.read_text(encoding="utf-8"))
    statement_saved = attestation.get("statement") or {}
    statement_current = _statement_for_bundle(bundle_dir)

    content_valid = statement_saved == statement_current
    signing = attestation.get("signing") or {}
    mode = str(signing.get("mode", "none")).strip().lower()

    signature_valid = False
    signature_error = None

    if mode == "none":
        signature_valid = True
    elif mode == "hmac-sha256":
        key_env = str(signing.get("key_env") or "PP_ATTEST_HMAC_KEY")
        key = os.getenv(key_env)
        if not key:
            signature_error = f"Missing environment variable for verification: {key_env}"
        else:
            expected = hmac.new(
                key.encode("utf-8"),
                _canonical_json_bytes(statement_saved),
                hashlib.sha256,
            ).hexdigest()
            given = str(signing.get("signature") or "")
            signature_valid = hmac.compare_digest(expected, given)
            if not signature_valid:
                signature_error = "Signature mismatch"
    else:
        signature_error = f"Unsupported signing mode: {mode}"

    ok = content_valid and signature_valid
    return {
        "ok": ok,
        "content_valid": content_valid,
        "signature_valid": signature_valid,
        "signature_error": signature_error,
        "mode": mode,
        "path": str(path),
    }
