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

    def test_context_mismatch_error_includes_path_and_anchor_details(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="pp-test-patch-mismatch-"))
        target = root / "text_utils.py"
        target.write_text('def slugify(text):\n    return text.strip().lower().replace(" ", "")\n', encoding="utf-8")

        diff = "\n".join(
            [
                "--- a/text_utils.py",
                "+++ b/text_utils.py",
                "@@ -1,3 +1,3 @@",
                " def slugify(text):",
                '-    return text.strip().lower().replace("_", "-")',
                '+    return text.strip().lower().replace(" ", "-")',
                "@@ -10,1 +10,1 @@",
                "-placeholder",
                "+placeholder",
                "",
            ]
        )

        policy = Policy(write_allowlist=["text_utils.py"])
        with self.assertRaises(ValueError) as ctx:
            apply_unified_diff(diff, root, policy)
        message = str(ctx.exception)
        self.assertIn("Context mismatch applying patch to text_utils.py", message)
        self.assertIn("anchors=", message)

    def test_apply_context_line_without_marker_on_indented_line(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="pp-test-patch-indented-context-"))
        target = root / "text_utils.py"
        original = 'def slugify(text):\n    return text.strip().lower().replace(" ", "")\n'
        target.write_text(original, encoding="utf-8")

        diff = "\n".join(
            [
                "--- a/text_utils.py",
                "+++ b/text_utils.py",
                "@@ -2,7 +2,7 @@",
                "def slugify(text):",
                '    return text.strip().lower().replace(" ", "")',
                "",
            ]
        )

        policy = Policy(write_allowlist=["text_utils.py"])
        changed = apply_unified_diff(diff, root, policy)
        self.assertEqual(changed, ["text_utils.py"])
        self.assertEqual(target.read_text(encoding="utf-8"), original)

    def test_context_only_hunk_single_mismatch_is_rejected(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="pp-test-patch-context-repair-"))
        target = root / "text_utils.py"
        target.write_text('def slugify(text):\n    return text.strip().lower().replace(" ", "")\n', encoding="utf-8")

        diff = "\n".join(
            [
                "--- a/text_utils.py",
                "+++ b/text_utils.py",
                "@@ -2,7 +2,7 @@",
                " def slugify(text):",
                '     return text.strip().lower().replace(" ", "-")',
                "",
            ]
        )

        policy = Policy(write_allowlist=["text_utils.py"])
        with self.assertRaises(ValueError) as ctx:
            apply_unified_diff(diff, root, policy)
        self.assertIn("Context mismatch applying patch to text_utils.py", str(ctx.exception))

    def test_single_hunk_with_unusable_anchors_is_rejected(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="pp-test-patch-rewrite-"))
        target = root / "stats_utils.py"
        target.write_text(
            "def median(values):\n"
            "    ordered = list(values)\n"
            "    mid = len(ordered) // 2\n"
            "    return ordered[mid]\n",
            encoding="utf-8",
        )

        diff = "\n".join(
            [
                "--- a/stats_utils.py",
                "+++ b/stats_utils.py",
                "@@ -10,7 +10,7 @@ def median(numbers):",
                "     sorted_numbers = sorted(numbers)",
                "     n = len(sorted_numbers)",
                "     mid = n // 2",
                "-    if n % 2 == 0:",
                "+    if n % 2 == 1:",
                "         return (sorted_numbers[mid - 1] + sorted_numbers[mid]) / 2",
                "     else:",
                "         return sorted_numbers[mid]",
                "",
            ]
        )

        policy = Policy(write_allowlist=["stats_utils.py"])
        with self.assertRaises(ValueError) as ctx:
            apply_unified_diff(diff, root, policy)
        self.assertIn("Context mismatch applying patch to stats_utils.py", str(ctx.exception))

    def test_apply_patch_with_fallback_rejects_noop_patch(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="pp-test-patch-noop-"))
        target = root / "text_utils.py"
        target.write_text('def slugify(text):\n    return text.strip().lower().replace(" ", "")\n', encoding="utf-8")

        diff = "\n".join(
            [
                "--- a/text_utils.py",
                "+++ b/text_utils.py",
                "@@ -1,2 +1,2 @@",
                " def slugify(text):",
                '     return text.strip().lower().replace(" ", "")',
                "",
            ]
        )

        policy = Policy(write_allowlist=["text_utils.py"])
        with self.assertRaises(ValueError) as ctx:
            apply_patch_with_fallback(diff, root, policy)
        self.assertIn("Patch contains no line-level edits", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
