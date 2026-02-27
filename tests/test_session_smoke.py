import json
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

    def test_replay_applies_final_patch_before_verification(self) -> None:
        workspace = Path(tempfile.mkdtemp(prefix="pp-test-replay-src-"))
        (workspace / "x.txt").write_text("0\n", encoding="utf-8")

        cmd = (
            "python -c \"import pathlib,sys; "
            "sys.exit(0 if pathlib.Path('x.txt').read_text().strip()=='1' else 1)\""
        )
        bundle = Path(tempfile.mkdtemp(prefix="pp-test-replay-bundle-")) / "proof_bundle"
        bundle.mkdir(parents=True, exist_ok=True)
        (bundle / "repro.json").write_text(
            json.dumps(
                {
                    "command": cmd,
                    "workspace_root": str(workspace),
                    "proof_targets": [{"name": "check", "cmd": cmd}],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        (bundle / "policy.json").write_text(
            json.dumps(
                {
                    "proof_targets": [{"name": "check", "cmd": cmd}],
                    "policy": {
                        "network": "deny",
                        "allowed_commands": [cmd],
                        "write_allowlist": ["**"],
                        "deny_write": [],
                        "limits": {
                            "max_attempts": 1,
                            "max_files_changed": 8,
                            "max_patch_bytes": 200000,
                            "per_command_timeout_sec": 120,
                        },
                        "minimize": False,
                        "sandbox": {
                            "backend": "copy",
                            "container_runtime": "docker",
                            "container_image": "python:3.11-slim",
                            "container_workdir": "/workspace",
                            "cpu_limit": None,
                            "memory_limit": None,
                        },
                        "attestation": {"enabled": False, "mode": "none", "key_env": "PP_ATTEST_HMAC_KEY"},
                    },
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        (bundle / "final.patch").write_text(
            "\n".join(
                [
                    "--- a/x.txt",
                    "+++ b/x.txt",
                    "@@ -1,1 +1,1 @@",
                    "-0",
                    "+1",
                    "",
                ]
            ),
            encoding="utf-8",
        )

        controller = SessionController(workspace)
        result = controller.replay(bundle, cwd_override=workspace)
        self.assertTrue(result["success"])

    def test_prove_runs_all_policy_targets(self) -> None:
        workspace = Path(tempfile.mkdtemp(prefix="pp-test-prove-"))
        policy_path = workspace / "pp.json"
        cmd1 = "python -c 'print(1)'"
        cmd2 = "python -c 'print(2)'"
        policy_path.write_text(
            json.dumps(
                {
                    "proof_targets": [
                        {"name": "one", "cmd": cmd1},
                        {"name": "two", "cmd": cmd2},
                    ],
                    "policy": {
                        "network": "deny",
                        "allowed_commands": [cmd1, cmd2],
                        "write_allowlist": ["**"],
                        "deny_write": [],
                        "limits": {
                            "max_attempts": 1,
                            "max_files_changed": 8,
                            "max_patch_bytes": 200000,
                            "per_command_timeout_sec": 120,
                        },
                        "minimize": False,
                    },
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        controller = SessionController(workspace)
        summary = controller.prove(policy_path=str(policy_path), provider_name="stub")
        self.assertTrue(summary.success)
        self.assertEqual(summary.attempts_used, 0)
        repro = json.loads((summary.proof_bundle_dir / "repro.json").read_text(encoding="utf-8"))
        self.assertEqual(len(repro["proof_targets"]), 2)


if __name__ == "__main__":
    unittest.main()
