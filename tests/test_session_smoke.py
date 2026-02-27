import os
import tempfile
import unittest
from pathlib import Path

from pp.attest import verify_attestation
from pp.session import SessionController


class SessionSmokeTests(unittest.TestCase):
    def test_run_success_without_attempts(self) -> None:
        workspace = Path(tempfile.mkdtemp(prefix="pp-test-session-"))
        (workspace / "README.md").write_text("x\n", encoding="utf-8")

        controller = SessionController(workspace)
        summary = controller.run("python -c 'print(1)'", provider_name="stub")

        self.assertTrue(summary.success)
        self.assertEqual(summary.attempts_used, 0)
        self.assertTrue(summary.final_patch_path.exists())
        self.assertTrue((summary.proof_bundle_dir / "repro.json").exists())

    def test_run_with_attestation(self) -> None:
        workspace = Path(tempfile.mkdtemp(prefix="pp-test-session-"))
        (workspace / "README.md").write_text("x\n", encoding="utf-8")

        os.environ["PP_ATTEST_HMAC_KEY"] = "session-test-key"
        controller = SessionController(workspace)
        summary = controller.run(
            "python -c 'print(1)'",
            provider_name="stub",
            attest=True,
            attestation_mode="hmac-sha256",
        )

        att_path = summary.proof_bundle_dir / "attestation.json"
        self.assertTrue(att_path.exists())
        verify = verify_attestation(summary.proof_bundle_dir)
        self.assertTrue(verify["ok"])


if __name__ == "__main__":
    unittest.main()
