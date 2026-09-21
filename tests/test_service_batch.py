"""Tests for concurrent NightRecon service detection."""

import unittest
from unittest.mock import patch

from nightrecon.service_detection import (
    ServiceDetectionResult,
    detect_services,
)


class ServiceBatchDetectionTests(unittest.TestCase):

    def test_invalid_worker_count_is_rejected(self):
        with self.assertRaises(ValueError):
            detect_services(
                address="127.0.0.1",
                ports=(22,),
                timeout=2.0,
                max_workers=0,
        )

    def test_empty_port_collection_is_rejected(self):
        with self.assertRaises(ValueError):
            detect_services(
                address="127.0.0.1",
                ports=(),
                timeout=2.0,
                max_workers=3,
        )

    def test_multiple_services_are_detected_and_sorted(self):
        def fake_detect(address, port, timeout):
            return ServiceDetectionResult(
                address=address,
                port=port,
                service={
                    22: "ssh",
                    80: "http",
                    443: "https",
                }.get(port, "unknown"),
                banner="",
            )

        with patch(
            "nightrecon.service_detection.detect_service",
            side_effect=fake_detect,
        ) as detector:
            results = detect_services(
                address="127.0.0.1",
                ports=(443, 22, 80),
                timeout=2.0,
                max_workers=3,
            )

        self.assertEqual(
            tuple(result.port for result in results),
            (22, 80, 443),
        )

        self.assertEqual(detector.call_count, 3)


if __name__ == "__main__":
    unittest.main()