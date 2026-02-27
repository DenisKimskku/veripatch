import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pp.config import Policy
from pp.patch import apply_patch_with_fallback, apply_unified_diff


class PatchApplyTests(unittest.TestCase):
    def test_apply_patch_with_allowlist(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="pp-test-patch-"))
        (root / "src").mkdir(parents=True, exist_ok=True)
        target = root / "src" / "app.py"
        target.write_text("a = 1\n", encoding="utf-8")

        diff = "\n".join(
            [
                "--- a/src/app.py",
                "+++ b/src/app.py",
                "@@ -1,1 +1,1 @@",
                "-a = 1",
                "+a = 2",
                "",
            ]
        )

        policy = Policy(write_allowlist=["src/**"])
        changed = apply_unified_diff(diff, root, policy)
        self.assertEqual(changed, ["src/app.py"])
        self.assertEqual(target.read_text(encoding="utf-8"), "a = 2\n")

    def test_deny_patch_outside_allowlist(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="pp-test-patch-"))
        (root / "secrets").mkdir(parents=True, exist_ok=True)
        target = root / "secrets" / "x.txt"
        target.write_text("a\n", encoding="utf-8")

        diff = "\n".join(
            [
                "--- a/secrets/x.txt",
                "+++ b/secrets/x.txt",
                "@@ -1,1 +1,1 @@",
                "-a",
                "+b",
                "",
            ]
        )

        policy = Policy(write_allowlist=["src/**"], deny_write=["secrets/**"])
        with self.assertRaises(ValueError):
            apply_unified_diff(diff, root, policy)

    def test_git_apply_is_preferred_in_git_repo(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="pp-test-patch-git-"))
        subprocess.run(["git", "init"], cwd=str(root), check=True, capture_output=True, text=True)
        (root / "src").mkdir(parents=True, exist_ok=True)
        target = root / "src" / "app.py"
        target.write_text("a = 1\n", encoding="utf-8")

        diff = "\n".join(
            [
                "diff --git a/src/app.py b/src/app.py",
                "--- a/src/app.py",
                "+++ b/src/app.py",
                "@@ -1,1 +1,1 @@",
                "-a = 1",
                "+a = 2",
                "",
            ]
        )

        policy = Policy(write_allowlist=["src/**"])
        with mock.patch("pp.patch.apply_unified_diff") as parser_apply:
            changed = apply_patch_with_fallback(diff, root, policy)
            parser_apply.assert_not_called()
        self.assertEqual(changed, ["src/app.py"])
        self.assertEqual(target.read_text(encoding="utf-8"), "a = 2\n")

    def test_apply_hunk_with_incorrect_line_numbers_using_context(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="pp-test-patch-context-"))
        target = root / "math_utils.py"
        target.write_text("def add(a, b):\n    return a + c\n", encoding="utf-8")

        diff = "\n".join(
            [
                "diff --git a/math_utils.py b/math_utils.py",
                "--- a/math_utils.py",
                "+++ b/math_utils.py",
                "@@ -2,7 +2,7 @@",
                " def add(a, b):",
                "-    return a + c",
                "+    return a + b",
                "",
            ]
        )

        policy = Policy(write_allowlist=["math_utils.py"])
        changed = apply_unified_diff(diff, root, policy)
        self.assertEqual(changed, ["math_utils.py"])
        self.assertEqual(target.read_text(encoding="utf-8"), "def add(a, b):\n    return a + b\n")

    def test_apply_hunk_with_missing_context_prefix(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="pp-test-patch-prefix-"))
        target = root / "math_utils.py"
        target.write_text("def add(a, b):\n    return a + c\n", encoding="utf-8")

        diff = "\n".join(
            [
                "--- a/math_utils.py",
                "+++ b/math_utils.py",
                "@@ -2,7 +2,7 @@",
                "def add(a, b):",
                "-    return a + c",
                "+    return a + b",
                "",
            ]
        )

        policy = Policy(write_allowlist=["math_utils.py"])
        changed = apply_unified_diff(diff, root, policy)
        self.assertEqual(changed, ["math_utils.py"])
        self.assertEqual(target.read_text(encoding="utf-8"), "def add(a, b):\n    return a + b\n")


if __name__ == "__main__":
    unittest.main()
