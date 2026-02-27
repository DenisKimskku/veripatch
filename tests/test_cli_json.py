import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from pp.cli import main


class CliJsonTests(unittest.TestCase):
    def test_doctor_json(self) -> None:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["doctor", "--command", "true", "--json"])
        self.assertEqual(rc, 0)
        payload = json.loads(buf.getvalue())
        self.assertIn("allowed_commands", payload)
        self.assertIn("sandbox_backend", payload)

    def test_run_json(self) -> None:
        workspace = Path(tempfile.mkdtemp(prefix="pp-test-cli-json-"))
        old_cwd = Path.cwd()
        try:
            os.chdir(workspace)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["run", "python -c 'print(1)'", "--provider", "stub", "--json"])
            self.assertEqual(rc, 0)
            payload = json.loads(buf.getvalue())
            self.assertTrue(payload["success"])
            self.assertIn("proof_bundle", payload)
        finally:
            os.chdir(old_cwd)


if __name__ == "__main__":
    unittest.main()
