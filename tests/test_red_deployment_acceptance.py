"""Tests for evidence-honest Red deployment acceptance."""

import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
RED_APP_ROOT = ROOT / "packages" / "red-night"
if str(RED_APP_ROOT) not in sys.path:
    sys.path.insert(0, str(RED_APP_ROOT))

from red_night_app.deployment_acceptance import (
    RedEnduranceQualification,
    RedHardwareQualification,
    evaluate_red_deployment_readiness,
)


class RedDeploymentAcceptanceTests(unittest.TestCase):
    def hardware(self, **overrides):
        values = {
            "hardware_id": "fixture-uefi-pc",
            "uefi_boot_verified": True,
            "secure_workspace_verified": True,
            "ephemeral_session_verified": True,
            "recovery_verified": True,
            "network_verified": True,
        }
        values.update(overrides)
        return RedHardwareQualification(**values)

    def endurance(self, **overrides):
        values = {
            "media_id": "fixture-usb",
            "continuous_hours": 24,
            "reboot_cycles": 20,
            "safe_remove_cycles": 20,
            "integrity_failures": 0,
        }
        values.update(overrides)
        return RedEnduranceQualification(**values)

    def test_automated_green_does_not_fake_manual_acceptance(self):
        result = evaluate_red_deployment_readiness(
            automated_gates_green=True,
            secure_boot_verified=False,
            hardware_qualifications=(),
            endurance_qualifications=(),
        )

        self.assertFalse(result.ready_for_production_deployment)
        self.assertIn("Secure Boot has not been verified", result.blockers)
        self.assertIn(
            "hardware compatibility matrix has no verified entries",
            result.blockers,
        )
        self.assertIn(
            "USB endurance qualification has not been recorded",
            result.blockers,
        )

    def test_complete_evidence_can_close_deployment_gate(self):
        result = evaluate_red_deployment_readiness(
            automated_gates_green=True,
            secure_boot_verified=True,
            hardware_qualifications=(self.hardware(),),
            endurance_qualifications=(self.endurance(),),
        )

        self.assertTrue(result.ready_for_production_deployment)
        self.assertEqual(result.blockers, ())

    def test_failed_hardware_or_endurance_remains_blocking(self):
        result = evaluate_red_deployment_readiness(
            automated_gates_green=True,
            secure_boot_verified=True,
            hardware_qualifications=(self.hardware(network_verified=False),),
            endurance_qualifications=(self.endurance(integrity_failures=1),),
        )

        self.assertFalse(result.ready_for_production_deployment)
        self.assertEqual(len(result.blockers), 2)


if __name__ == "__main__":
    unittest.main()
