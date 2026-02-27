import tempfile
import unittest
from pathlib import Path

from pp.runner import Sandbox, _build_container_command


class ContainerRunnerTests(unittest.TestCase):
    def test_build_container_command_includes_policy_controls(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="pp-test-runner-"))
        sandbox = Sandbox(
            root=root,
            backend="container",
            workspace_backend="copy",
            control_root=root,
            container_runtime="docker",
            container_image="python:3.11-slim",
            container_workdir="/workspace",
            network="deny",
            cpu_limit="2",
            memory_limit="1g",
        )

        cmd = _build_container_command("pytest -q", root, sandbox)
        joined = " ".join(cmd)

        self.assertIn("docker run", joined)
        self.assertIn("--network none", joined)
        self.assertIn("--cpus 2", joined)
        self.assertIn("--memory 1g", joined)
        self.assertIn("python:3.11-slim", joined)


if __name__ == "__main__":
    unittest.main()
