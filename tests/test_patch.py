import tempfile
import unittest
from pathlib import Path

from pp.config import Policy
from pp.patch import apply_unified_diff


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


if __name__ == "__main__":
    unittest.main()
