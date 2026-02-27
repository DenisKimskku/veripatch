import tempfile
import unittest
from pathlib import Path

from pp.context import extract_context


class ContextExtractionTests(unittest.TestCase):
    def test_container_workdir_path_mapping(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="pp-test-context-"))
        target = root / "src" / "app.py"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("line1\nline2\nline3\n", encoding="utf-8")

        output = 'Traceback (most recent call last):\n  File "/workspace/src/app.py", line 2, in <module>\nAssertionError: boom\n'
        ctx = extract_context(output, root, container_workdir="/workspace")

        self.assertTrue(ctx.locations)
        self.assertEqual(ctx.locations[0].file, "src/app.py")
        self.assertEqual(ctx.locations[0].line, 2)
        key = "src/app.py:2"
        self.assertIn(key, ctx.snippets)
        self.assertIn(">>", ctx.snippets[key])


if __name__ == "__main__":
    unittest.main()
