import unittest

from stats_utils import median


class StatsTests(unittest.TestCase):
    def test_median_odd_values(self):
        self.assertEqual(median([9, 1, 5]), 5)


if __name__ == "__main__":
    unittest.main()
