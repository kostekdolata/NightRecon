"""Tests for evidence-based operating-system fingerprinting."""

import unittest

from nightrecon.os_fingerprint import (
    OperatingSystemEvidence,
    OperatingSystemFingerprint,
    build_operating_system_fingerprint,
)
from nightrecon.service_detection import ServiceDetectionResult
from nightrecon.service_fingerprint import ServiceFingerprint


class OperatingSystemFingerprintTests(unittest.TestCase):
    def test_single_explicit_platform_hint_produces_medium_confidence(self):
        services = (
            ServiceDetectionResult(
                address="192.0.2.10",
                port=22,
                service="ssh",
                banner="",
                service_fingerprint=ServiceFingerprint(
                    protocol="ssh",
                    product="OpenSSH",
                    version="9.6p1",
                    platform="Ubuntu",
                    source="banner",
                    evidence=(
                        "SSH-2.0-OpenSSH_9.6p1 "
                        "Ubuntu-3ubuntu13.14"
                    ),
                    confidence="high",
                ),
            ),
        )

        result = build_operating_system_fingerprint(
            services
        )

        self.assertEqual(
            result,
            OperatingSystemFingerprint(
                platform="Ubuntu",
                family="Linux",
                confidence="medium",
                evidence=(
                    OperatingSystemEvidence(
                        address="192.0.2.10",
                        port=22,
                        service="ssh",
                        platform="Ubuntu",
                        family="Linux",
                        source="banner",
                        evidence=(
                            "SSH-2.0-OpenSSH_9.6p1 "
                            "Ubuntu-3ubuntu13.14"
                        ),
                    ),
                ),
            ),
        )

    def test_agreeing_independent_services_raise_confidence(self):
        services = (
            ServiceDetectionResult(
                address="192.0.2.10",
                port=22,
                service="ssh",
                banner="",
                service_fingerprint=ServiceFingerprint(
                    protocol="ssh",
                    product="OpenSSH",
                    version="9.6p1",
                    platform="Ubuntu",
                    source="banner",
                    evidence="ssh evidence",
                    confidence="high",
                ),
            ),
            ServiceDetectionResult(
                address="192.0.2.10",
                port=443,
                service="https",
                banner="",
                service_fingerprint=ServiceFingerprint(
                    protocol="http",
                    product="Apache",
                    version="2.4.58",
                    platform="Ubuntu",
                    source="http-server",
                    evidence="Apache/2.4.58 (Ubuntu)",
                    confidence="high",
                ),
            ),
        )

        result = build_operating_system_fingerprint(
            services
        )

        self.assertEqual(result.platform, "Ubuntu")
        self.assertEqual(result.family, "Linux")
        self.assertEqual(result.confidence, "high")
        self.assertEqual(len(result.evidence), 2)

    def test_conflicting_platforms_are_reported_without_guessing(self):
        services = (
            ServiceDetectionResult(
                address="192.0.2.10",
                port=22,
                service="ssh",
                banner="",
                service_fingerprint=ServiceFingerprint(
                    protocol="ssh",
                    platform="Ubuntu",
                    source="banner",
                    evidence="ssh evidence",
                    confidence="high",
                ),
            ),
            ServiceDetectionResult(
                address="192.0.2.10",
                port=80,
                service="http",
                banner="",
                service_fingerprint=ServiceFingerprint(
                    protocol="http",
                    platform="FreeBSD",
                    source="http-server",
                    evidence="http evidence",
                    confidence="high",
                ),
            ),
        )

        result = build_operating_system_fingerprint(
            services
        )

        self.assertEqual(result.platform, "")
        self.assertEqual(result.family, "")
        self.assertEqual(result.confidence, "conflicting")
        self.assertEqual(
            result.candidates,
            ("FreeBSD", "Ubuntu"),
        )

    def test_known_platforms_map_to_os_families(self):
        services = (
            ServiceDetectionResult(
                address="192.0.2.10",
                port=80,
                service="http",
                banner="",
                service_fingerprint=ServiceFingerprint(
                    protocol="http",
                    platform="Debian",
                    source="http-server",
                    evidence="Apache/2.4.62 (Debian)",
                    confidence="high",
                ),
            ),
        )

        result = build_operating_system_fingerprint(
            services
        )

        self.assertEqual(result.platform, "Debian")
        self.assertEqual(result.family, "Linux")


if __name__ == "__main__":
    unittest.main()
