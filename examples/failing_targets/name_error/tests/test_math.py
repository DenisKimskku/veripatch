import unittest

from math_utils import add


class MathTests(unittest.TestCase):
    def test_add(self):
        self.assertEqual(add(1, 1), 2)


if __name__ == "__main__":
    unittest.main()
