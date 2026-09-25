"""CLI integration tests for NightRecon service detection."""

import contextlib
import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from nightrecon.cli import main
from nightrecon.service_detection import ServiceDetectionResult
from nightrecon.service_fingerprint import ServiceFingerprint
from nightrecon.software_identity import SoftwareIdentity
from nightrecon.tcp_scanner import TcpPortResult


class CliServiceDetectionTests(unittest.TestCase):

    def test_https_service_displays_tls_metadata(self):
        scan_results = (
            TcpPortResult(
                address="127.0.0.1",
                port=443,
                is_open=True,
                error_code=0,
            ),
        )

        service_results = (
            ServiceDetectionResult(
                address="127.0.0.1",
                port=443,
                service="https",
                banner="",
                tls_version="TLSv1.3",
                tls_cipher="TLS_AES_256_GCM_SHA384",
                tls_certificate_subject="commonName=example.test",
                tls_certificate_issuer=(
                    "organizationName=NightRecon Test CA"
                ),
                tls_certificate_not_before="2026-01-01T00:00:00+00:00",
                tls_certificate_not_after="2027-01-01T00:00:00+00:00",
                tls_certificate_sans=(
                    "example.test",
                    "www.example.test",
                ),
                tls_certificate_sha256=(
                    "00112233445566778899aabbccddeeff"
                    "00112233445566778899aabbccddeeff"
                ),
                http_status="HTTP/1.1 200 OK",
                http_server="nginx/1.24.0",
                security_headers_present=(
                    "content-security-policy",
                    "strict-transport-security",
                    "x-content-type-options",
                ),
                security_headers_missing=(
                    "x-frame-options",
                    "referrer-policy",
                    "permissions-policy",
                ),
                software_identity=SoftwareIdentity(
                    product="nginx",
                    version="1.24.0",
                    source="http-server",
                    evidence="nginx/1.24.0",
                ),
                service_fingerprint=ServiceFingerprint(
                    protocol="http",
                    product="nginx",
                    version="1.24.0",
                    platform="Ubuntu",
                    source="http-server",
                    evidence="nginx/1.24.0 (Ubuntu)",
                    confidence="high",
                ),
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
                "443",
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
                        "nightrecon.cli.ResultStore"
                    ) as store_class:
                        store_class.return_value.save_report.return_value = (
                            Path("results/test.json")
                        )

                        with patch("nightrecon.cli.NightReconLogger"):
                            with contextlib.redirect_stdout(stdout):
                                with contextlib.redirect_stderr(stderr):
                                    try:
                                        main()
                                        exit_code = 0
                                    except SystemExit as exc:
                                        exit_code = exc.code

        self.assertEqual(exit_code, 0)
        self.assertEqual(stderr.getvalue(), "")

        output = stdout.getvalue()

        self.assertIn(
            "SERVICE 127.0.0.1:443 https",
            output,
        )
        self.assertIn(
            "TLS Version: TLSv1.3",
            output,
        )
        self.assertIn(
            "TLS Cipher: TLS_AES_256_GCM_SHA384",
            output,
        )
        self.assertIn(
            "Certificate Subject: commonName=example.test",
            output,
        )
        self.assertIn(
            "Certificate Issuer: organizationName=NightRecon Test CA",
            output,
        )
        self.assertIn(
            "Certificate Valid From: 2026-01-01T00:00:00+00:00",
            output,
        )
        self.assertIn(
            "Certificate Valid Until: 2027-01-01T00:00:00+00:00",
            output,
        )
        self.assertIn(
            "Certificate SANs: example.test, www.example.test",
            output,
        )
        self.assertIn(
            (
                "Certificate SHA-256: "
                "00112233445566778899aabbccddeeff"
                "00112233445566778899aabbccddeeff"
            ),
              output,
        )
        self.assertIn(
            "HTTP Status: HTTP/1.1 200 OK",
            output,
        )
        self.assertIn(
            "Server: nginx/1.24.0",
            output,
        )
        self.assertIn(
            "Software: nginx 1.24.0",
            output,
        )
        self.assertIn(
            "Fingerprint: protocol=http product=nginx "
            "version=1.24.0 platform=Ubuntu confidence=high",
            output,
        )
        self.assertIn(
            "Security Headers Present: "
            "content-security-policy, "
            "strict-transport-security, "
            "x-content-type-options",
            output,
        )
        self.assertIn(
            "Security Headers Missing: "
            "x-frame-options, "
            "referrer-policy, "
            "permissions-policy",
            output,
        )


    def test_service_probe_intensity_is_forwarded_when_enabled(self):
        scan_results = (
            TcpPortResult(
                address="127.0.0.1",
                port=9000,
                is_open=True,
                error_code=0,
            ),
        )

        service_results = (
            ServiceDetectionResult(
                address="127.0.0.1",
                port=9000,
                service="http",
                banner="",
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
                "9000",
                "--service-probe-intensity",
                "3",
            ],
        ):
            with patch(
                "nightrecon.cli.scan_tcp_ports",
                return_value=scan_results,
            ):
                with patch(
                    "nightrecon.cli.detect_services",
                    return_value=service_results,
                ) as detector:
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
        detector.assert_called_once_with(
            address="127.0.0.1",
            ports=(9000,),
            timeout=2.0,
            max_workers=50,
            probe_intensity=3,
        )

    def test_service_detection_runs_only_for_open_ports(self):
        scan_results = (
            TcpPortResult(
                address="127.0.0.1",
                port=80,
                is_open=True,
                error_code=0,
            ),
            TcpPortResult(
                address="127.0.0.1",
                port=443,
                is_open=False,
                error_code=10061,
            ),
        )

        service_results = (
            ServiceDetectionResult(
                address="127.0.0.1",
                port=80,
                service="http",
                banner="Server: NightRecon-Test",
                http_status="HTTP/1.1 200 OK",
                http_server="nginx/1.24.0",
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
                "80,443",
            ],
        ):
            with patch(
                "nightrecon.cli.scan_tcp_ports",
                return_value=scan_results,
            ):
                with patch(
                    "nightrecon.cli.detect_services",
                    return_value=service_results,
                ) as detector:
                    with patch(
                        "nightrecon.cli.ResultStore"
                    ) as store_class:
                        store_class.return_value.save_report.return_value = (
                            Path("results/test.json")
                        )

                        with patch("nightrecon.cli.NightReconLogger"):
                            with contextlib.redirect_stdout(stdout):
                                with contextlib.redirect_stderr(stderr):
                                    try:
                                        main()
                                        exit_code = 0
                                    except SystemExit as exc:
                                        exit_code = exc.code

        self.assertEqual(exit_code, 0)
        self.assertEqual(stderr.getvalue(), "")

        detector.assert_called_once_with(
            address="127.0.0.1",
            ports=(80,),
            timeout=2.0,
            max_workers=50,
        )

        report = store_class.return_value.save_report.call_args.args[0]

        self.assertEqual(len(report.services), 1)
        self.assertEqual(report.services[0].port, 80)
        self.assertEqual(report.services[0].service, "http")

        self.assertIn(
            "SERVICE 127.0.0.1:80 http",
            stdout.getvalue(),
        )
        self.assertIn(
            "Banner: Server: NightRecon-Test",
            stdout.getvalue(),
        )
        self.assertIn(
            "HTTP Status: HTTP/1.1 200 OK",
            stdout.getvalue(),
        )
        self.assertIn(
            "Server: nginx/1.24.0",
            stdout.getvalue(),
        )


if __name__ == "__main__":
    unittest.main()
