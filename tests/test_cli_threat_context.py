"""CLI integration tests for NightRecon threat-context intelligence."""

import contextlib
import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from nightrecon.cli import main
from nightrecon.service_detection import ServiceDetectionResult
from nightrecon.software_identity import SoftwareIdentity
from nightrecon.tcp_scanner import TcpPortResult
from nightrecon.threat_context import ThreatContextResult
from nightrecon.vulnerability_intelligence import (
    ServiceVulnerabilityResult,
    VulnerabilityFinding,
    VulnerabilityLookupResult,
)


class CliThreatContextTests(unittest.TestCase):
    def test_threat_context_requires_vulnerability_lookup(self):
        stderr = io.StringIO()

        with patch.object(
            sys,
            "argv",
            [
                "nightrecon",
                "scan",
                "127.0.0.1",
                "--scope",
                "127.0.0.1",
                "--threat-context",
            ],
        ):
            with contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as exc:
                    main()

        self.assertEqual(exc.exception.code, 2)
        self.assertIn(
            "--threat-context requires --vuln-lookup",
            stderr.getvalue(),
        )

    def test_threat_context_is_enriched_persisted_and_displayed(self):
        software = SoftwareIdentity(
            product="nginx",
            version="1.24.0",
            source="http-server",
            evidence="nginx/1.24.0",
        )
        scan_results = (
            TcpPortResult(
                address="127.0.0.1",
                port=80,
                is_open=True,
                error_code=0,
            ),
        )
        service_results = (
            ServiceDetectionResult(
                address="127.0.0.1",
                port=80,
                service="http",
                banner="",
                software_identity=software,
            ),
        )
        vulnerability_results = (
            ServiceVulnerabilityResult(
                address="127.0.0.1",
                port=80,
                service="http",
                lookup=VulnerabilityLookupResult(
                    provider="nvd",
                    software_identity=software,
                    findings=(
                        VulnerabilityFinding(
                            vulnerability_id="CVE-2026-1234",
                            source="nvd",
                            summary="Example vulnerability.",
                        ),
                    ),
                ),
            ),
        )
        threat_context = (
            ThreatContextResult(
                vulnerability_id="CVE-2026-1234",
                known_exploited=True,
                kev_date_added="2026-09-01",
                kev_due_date="2026-09-22",
                kev_known_ransomware_campaign_use="Known",
                kev_required_action="Apply vendor mitigations.",
                epss_probability=0.42,
                epss_percentile=0.97,
                epss_date="2026-09-24",
            ),
        )

        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch.object(
            sys,
            "argv",
            [
                "nightrecon",
                "scan",
                "127.0.0.1",
                "--scope",
                "127.0.0.1",
                "--ports",
                "80",
                "--vuln-lookup",
                "--threat-context",
            ],
        ):
            with patch(
                "nightrecon.cli.scan_tcp_ports",
                return_value=scan_results,
            ):
                with patch(
                    "nightrecon.cli.detect_services",
                    return_value=service_results,
                ):
                    with patch(
                        "nightrecon.cli.enrich_service_vulnerabilities",
                        return_value=vulnerability_results,
                    ):
                        with patch(
                            "nightrecon.cli.CisaKevProvider"
                        ) as kev_class:
                            kev_provider = kev_class.return_value

                            with patch(
                                "nightrecon.cli.FirstEpssProvider"
                            ) as epss_class:
                                epss_provider = epss_class.return_value

                                with patch(
                                    "nightrecon.cli.enrich_threat_context",
                                    return_value=threat_context,
                                ) as enrich_context:
                                    with patch(
                                        "nightrecon.cli.ResultStore"
                                    ) as store_class:
                                        store_class.return_value.save_report.return_value = (
                                            Path("results/test.json")
                                        )

                                        with patch(
                                            "nightrecon.cli.NightReconLogger"
                                        ):
                                            with contextlib.redirect_stdout(stdout):
                                                with contextlib.redirect_stderr(stderr):
                                                    try:
                                                        main()
                                                        exit_code = 0
                                                    except SystemExit as exc:
                                                        exit_code = exc.code

        self.assertEqual(exit_code, 0)
        self.assertEqual(stderr.getvalue(), "")

        enrich_context.assert_called_once_with(
            vulnerabilities=vulnerability_results,
            kev_provider=kev_provider,
            epss_provider=epss_provider,
        )

        report = store_class.return_value.save_report.call_args.args[0]
        self.assertTrue(report.threat_context_enabled)
        self.assertEqual(report.threat_context, threat_context)

        output = stdout.getvalue()
        self.assertIn(
            "THREAT CONTEXT CVE-2026-1234 known_exploited=yes",
            output,
        )
        self.assertIn(
            "EPSS probability=0.42 percentile=0.97 date=2026-09-24",
            output,
        )
        self.assertIn(
            "KEV date_added=2026-09-01 due_date=2026-09-22",
            output,
        )
        self.assertIn(
            "Threat Context Summary: cves=1 known_exploited=1 "
            "epss_available=1 provider_errors=0",
            output,
        )
        self.assertIn(
            "Max EPSS: probability=0.42 percentile=0.97",
            output,
        )


if __name__ == "__main__":
    unittest.main()
