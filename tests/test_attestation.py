import os
import tempfile
import unittest
from pathlib import Path

from pp.attest import create_attestation, verify_attestation


class AttestationTests(unittest.TestCase):
    def test_create_and_verify_hmac_attestation(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="pp-test-attest-"))
        bundle = root / "proof_bundle"
        bundle.mkdir(parents=True, exist_ok=True)
        (bundle / "repro.json").write_text('{"ok":true}\n', encoding="utf-8")
        (bundle / "final.patch").write_text("", encoding="utf-8")

        os.environ["PP_ATTEST_HMAC_KEY"] = "test-key"
        create_attestation(bundle, mode="hmac-sha256", key_env="PP_ATTEST_HMAC_KEY")

        result = verify_attestation(bundle)
        self.assertTrue(result["ok"])
        self.assertTrue(result["content_valid"])
        self.assertTrue(result["signature_valid"])

        # Tamper with bundle and ensure verification fails.
        (bundle / "repro.json").write_text('{"ok":false}\n', encoding="utf-8")
        tampered = verify_attestation(bundle)
        self.assertFalse(tampered["ok"])
        self.assertFalse(tampered["content_valid"])


if __name__ == "__main__":
    unittest.main()
