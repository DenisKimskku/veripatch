import unittest

from pp.config import Policy


class PolicyCommandTests(unittest.TestCase):
    def test_allowed_argv_matches_split_command(self) -> None:
        policy = Policy(
            allowed_commands=[],
            allowed_argv=[["python", "-c", "print(1)"]],
        )

        allowed, argv = policy.command_execution("python -c 'print(1)'")
        self.assertTrue(allowed)
        self.assertEqual(argv, ["python", "-c", "print(1)"])

    def test_disallow_unlisted_command(self) -> None:
        policy = Policy(
            allowed_commands=[],
            allowed_argv=[["python", "-c", "print(1)"]],
        )

        allowed, argv = policy.command_execution("python -c 'print(2)'")
        self.assertFalse(allowed)
        self.assertIsNone(argv)


if __name__ == "__main__":
    unittest.main()
