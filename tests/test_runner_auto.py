import subprocess
import tempfile
import unittest
from pathlib import Path

from pp.config import Policy
from pp.runner import cleanup_sandbox, create_sandbox


class RunnerAutoSandboxTests(unittest.TestCase):
    def test_auto_uses_copy_when_git_repo_is_dirty(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="pp-test-runner-auto-"))
        subprocess.run(["git", "init"], cwd=str(root), check=True, capture_output=True, text=True)
        (root / "untracked.txt").write_text("x\n", encoding="utf-8")

        policy = Policy()
        policy.sandbox.backend = "auto"

        sandbox = create_sandbox(root, policy)
        try:
            self.assertEqual(sandbox.workspace_backend, "copy")
            self.assertEqual(sandbox.backend, "native")
        finally:
            cleanup_sandbox(sandbox)


if __name__ == "__main__":
    unittest.main()
