"""No-Qt dependency tests for the passive startup host-information view."""
import unittest

from red_night_app.host_preflight_view import describe_host_preflight


class HostPreflightViewTests(unittest.TestCase):
    def fixture(self):
        return {
            "schema": 1,
            "os": "Windows",
            "architecture": "AMD64",
            "collected_at": "2026-11-04T23:00:00+00:00",
            "addresses": [
                {"interface": "Wi-Fi", "address": "192.0.2.12"},
                {"interface": "VPN", "address": "2001:db8::12"},
            ],
            "routes": [{"destination": "192.0.2.0/24", "gateway": "192.0.2.1"}],
            "tools": [
                {"tool": "nmap", "state": "unverified-present", "path": "C:/Users/private/nmap.exe"},
                {"tool": "tshark", "state": "missing"},
                {"tool": "nuclei", "state": "missing"},
            ],
            "errors": ["secret-auth-token-DO-NOT-PRINT"],
        }

    def test_view_contains_local_addresses_and_candidate_states(self):
        summary = describe_host_preflight(self.fixture())
        self.assertIn("192.0.2.12", summary)
        self.assertIn("2001:db8::12", summary)
        self.assertIn("192.0.2.0/24", summary)
        self.assertIn("nmap: unverified-present", summary)
        self.assertIn("No network scan performed", summary)

    def test_never_prints_binary_paths_secrets_or_untrusted_values(self):
        summary = describe_host_preflight(self.fixture())
        self.assertNotIn("C:/Users/private", summary)
        self.assertNotIn("secret-auth-token", summary)
        self.assertNotIn("execution-approved", summary)

    def test_missing_metadata_is_honest_and_does_not_infer_scope(self):
        report = {"schema": 1, "os": "Linux", "architecture": "x86_64",
                  "addresses": [], "routes": [], "tools": [], "errors": []}
        summary = describe_host_preflight(report)
        self.assertIn("No interface IP addresses available", summary)
        self.assertIn("No usable route data", summary)
        self.assertIn("Detected addresses do not grant scope", summary)

    def test_invalid_snapshot_fails_without_evidence(self):
        self.assertIn("unavailable", describe_host_preflight({"schema": 900}))


if __name__ == "__main__":
    unittest.main()
