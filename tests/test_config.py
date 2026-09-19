"""Tests for NightRecon configuration."""

import unittest

from nightrecon.config import NightReconConfig


class ConfigTests(unittest.TestCase):
    def test_default_configuration(self):
        config = NightReconConfig()

        self.assertEqual(config.connect_timeout, 2.0)
        self.assertEqual(config.max_workers, 50)
        self.assertEqual(config.results_dir, "results")
        self.assertEqual(config.logs_dir, "logs")

    def test_custom_configuration(self):
        config = NightReconConfig(
            connect_timeout=5.0,
            max_workers=10,
            results_dir="custom-results",
            logs_dir="custom-logs",
        )

        self.assertEqual(config.connect_timeout, 5.0)
        self.assertEqual(config.max_workers, 10)
        self.assertEqual(config.results_dir, "custom-results")
        self.assertEqual(config.logs_dir, "custom-logs")

    def test_invalid_timeout_is_rejected(self):
        with self.assertRaises(ValueError):
            NightReconConfig(connect_timeout=0)

    def test_invalid_worker_count_is_rejected(self):
        with self.assertRaises(ValueError):
            NightReconConfig(max_workers=0)

    def test_empty_results_directory_is_rejected(self):
        with self.assertRaises(ValueError):
            NightReconConfig(results_dir="   ")

    def test_empty_logs_directory_is_rejected(self):
        with self.assertRaises(ValueError):
            NightReconConfig(logs_dir="")


if __name__ == "__main__":
    unittest.main()
