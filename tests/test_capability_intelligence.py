"""Tests for exposure indicators, device roles, prioritisation, and validation lifecycle."""

import unittest

from nightrecon_red_engine.credential_exposure import detect_credential_exposure
from nightrecon_red_engine.device_fingerprint import fingerprint_device_role
from nightrecon_red_engine.exposure_prioritization import (
    ExposureEvidence,
    prioritize_exposure,
)
from nightrecon_red_engine.service_detection import ServiceDetectionResult
from nightrecon_red_engine.validation_sessions import (
    ValidationSession,
    ValidationSessionState,
)


class CapabilityIntelligenceTests(unittest.TestCase):
    def test_credential_detector_suppresses_secret_value(self):
        findings = detect_credential_exposure(
            "Authorization: Bearer very-secret-token",
            location="http-request",
        )
        self.assertEqual(len(findings), 1)
        self.assertNotIn("very-secret-token", str(findings[0]))
        self.assertTrue(findings[0].fingerprint)

    def test_windows_device_role_uses_observed_services(self):
        result = fingerprint_device_role((
            ServiceDetectionResult(
                address="192.0.2.10", port=135, service="msrpc", banner=""
            ),
            ServiceDetectionResult(
                address="192.0.2.10", port=445, service="smb", banner=""
            ),
        ))
        self.assertIsNotNone(result)
        self.assertEqual(result.role, "windows-host")
        self.assertEqual(result.confidence, "high")

    def test_priority_uses_reachability_kev_and_validation_evidence(self):
        result = prioritize_exposure(ExposureEvidence(
            vulnerability_id="CVE-TEST-1",
            reachable=True,
            cvss_score=9.8,
            kev_listed=True,
            epss_probability=0.8,
            validation_state="confirmed",
            preconditions_met=True,
            identity_path_present=True,
        ))
        self.assertEqual(result.priority, "high")
        self.assertEqual(result.exploitability_confidence, "confirmed")

    def test_validation_session_enforces_lifecycle(self):
        session = ValidationSession(
            session_id="s1",
            module_id="service.tcp-property-proof",
            target="192.0.2.10",
        )
        session = session.transition(ValidationSessionState.APPROVED)
        session = session.transition(ValidationSessionState.RUNNING)
        session = session.transition(
            ValidationSessionState.CONFIRMED,
            evidence_ids=("e1",),
        )
        self.assertEqual(session.state, ValidationSessionState.CONFIRMED)
        with self.assertRaises(ValueError):
            session.transition(ValidationSessionState.RUNNING)


if __name__ == "__main__":
    unittest.main()
