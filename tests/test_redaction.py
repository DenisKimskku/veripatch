import unittest

from pp.redaction import redact_text


class RedactionTests(unittest.TestCase):
    def test_redacts_basic_secret_patterns(self) -> None:
        raw = "api_key=abcd1234efgh5678 email=a@b.com phone=415-555-1234"
        out = redact_text(raw)
        self.assertNotIn("abcd1234efgh5678", out)
        self.assertIn("[REDACTED]", out)
        self.assertIn("[REDACTED_EMAIL]", out)
        self.assertIn("[REDACTED_PHONE]", out)


if __name__ == "__main__":
    unittest.main()
