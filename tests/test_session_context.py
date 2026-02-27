import tempfile
import unittest
from pathlib import Path

from pp.config import Policy
from pp.context import extract_context
from pp.session import SessionController


class SessionContextTests(unittest.TestCase):
    def test_augments_test_only_context_with_allowlisted_source(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="pp-test-session-context-"))
        (root / "tests").mkdir(parents=True, exist_ok=True)
        (root / "tests" / "test_text.py").write_text(
            'from text_utils import slugify\n\nassert slugify("Hello World") == "hello-world"\n',
            encoding="utf-8",
        )
        (root / "text_utils.py").write_text(
            'def slugify(text):\n    return text.strip().lower().replace(" ", "")\n',
            encoding="utf-8",
        )

        result_text = (
            "Traceback (most recent call last):\n"
            f'  File "{(root / "tests" / "test_text.py").as_posix()}", line 3, in <module>\n'
            'AssertionError: \'helloworld\' != \'hello-world\'\n'
        )
        context = extract_context(result_text, root)
        self.assertTrue(all(key.startswith("tests/test_text.py:") for key in context.snippets))

        controller = SessionController(root)
        policy = Policy(write_allowlist=["text_utils.py"], deny_write=["tests/**"])
        augmented = controller._augment_context_with_allowlist(context, root, policy)

        source_keys = [key for key in augmented.snippets if key.startswith("text_utils.py:")]
        self.assertTrue(source_keys)
        self.assertIn("def slugify(text):", augmented.snippets[source_keys[0]])


if __name__ == "__main__":
    unittest.main()
