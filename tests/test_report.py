"""Tests for NightRecon scan reports."""

import unittest

from nightrecon import report
from nightrecon.report import TcpScanReport
from nightrecon.service_detection import ServiceDetectionResult
from nightrecon.session import ScanSession
from nightrecon.targets import parse_target
from nightrecon.tcp_scanner import TcpPortResult


class TcpScanReportTests(unittest.TestCase):

    def create_report(self):
        target = parse_target("127.0.0.1")

        session = ScanSession.create(
            target=target,
            scope_rules=("127.0.0.1",),
        )

        results = (
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

        services = (
            ServiceDetectionResult(
                address="127.0.0.1",
                port=80,
                service="http",
                banner="",
                http_status="HTTP/1.1 200 OK",
                http_server="nginx/1.24.0",
            ),
        )

        return TcpScanReport.create(
            session=session,
            resolved_addresses=("127.0.0.1",),
            ports_requested=(80, 443),
            results=results,
            services=services,
        )



    def test_report_dictionary_contains_tls_metadata(self):
        target = parse_target("127.0.0.1")

        session = ScanSession.create(
            target=target,
            scope_rules=("127.0.0.1",),
        )

        report = TcpScanReport.create(
            session=session,
            resolved_addresses=("127.0.0.1",),
            ports_requested=(443,),
            results=(
                TcpPortResult(
                    address="127.0.0.1",
                    port=443,
                    is_open=True,
                    error_code=0,
                ),
            ),
            services=(
                ServiceDetectionResult(
                    address="127.0.0.1",
                    port=443,
                    service="https",
                    banner="",
                    tls_version="TLSv1.3",
                    tls_cipher="TLS_AES_256_GCM_SHA384",
                    tls_certificate_subject=(
                        "commonName=example.test"
                    ),
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
                ),
            ),
        )

        data = report.to_dict()
        service = data["services"][0]

        self.assertEqual(service["tls_version"], "TLSv1.3")
        self.assertEqual(
            service["tls_cipher"],
            "TLS_AES_256_GCM_SHA384",
        )
        self.assertEqual(
            service["tls_certificate_subject"],
            "commonName=example.test",
        )
        self.assertEqual(
            service["tls_certificate_issuer"],
            "organizationName=NightRecon Test CA",
        )
        self.assertEqual(
            service["tls_certificate_not_before"],
            "2026-01-01T00:00:00+00:00",
        )
        self.assertEqual(
            service["tls_certificate_not_after"],
            "2027-01-01T00:00:00+00:00",
        )
        self.assertEqual(
            service["tls_certificate_sans"],
            ("example.test", "www.example.test"),
        )
        self.assertEqual(
            service["tls_certificate_sha256"],
        (
            "00112233445566778899aabbccddeeff"
            "00112233445566778899aabbccddeeff"
        ),
    )

    def test_report_dictionary_contains_http_metadata(self):
        report = self.create_report()

        data = report.to_dict()

        self.assertEqual(
            data["services"][0]["http_status"],
            "HTTP/1.1 200 OK",
        )
        self.assertEqual(
            data["services"][0]["http_server"],
            "nginx/1.24.0",
        )

    def test_report_is_completed(self):
        report = self.create_report()

        self.assertEqual(report.status, "completed")

    def test_report_preserves_session_data(self):
        report = self.create_report()

        self.assertEqual(report.target, "127.0.0.1")
        self.assertEqual(report.target_type, "ipv4")
        self.assertEqual(report.scope, ("127.0.0.1",))

    def test_report_contains_requested_ports(self):
        report = self.create_report()

        self.assertEqual(
            report.ports_requested,
            (80, 443),
        )

    def test_open_ports_only_returns_open_results(self):
        report = self.create_report()

        self.assertEqual(len(report.open_ports), 1)
        self.assertEqual(report.open_ports[0].port, 80)

    def test_report_contains_service_results(self):
        report = self.create_report()

        self.assertEqual(len(report.services), 1)
        self.assertEqual(report.services[0].port, 80)
        self.assertEqual(report.services[0].service, "http")
        self.assertEqual(report.services[0].banner, "")

    def test_report_converts_to_dictionary(self):
        report = self.create_report()

        data = report.to_dict()

        self.assertEqual(data["status"], "completed")
        self.assertEqual(
            data["resolved_addresses"],
            ("127.0.0.1",),
        )
        self.assertEqual(
            data["ports_requested"],
            (80, 443),
        )

        self.assertEqual(len(data["results"]), 2)
        self.assertEqual(data["results"][0]["port"], 80)
        self.assertTrue(data["results"][0]["is_open"])

        self.assertEqual(len(data["services"]), 1)
        self.assertEqual(data["services"][0]["port"], 80)
        self.assertEqual(
            data["services"][0]["service"],
            "http",
        )


if __name__ == "__main__":
    unittest.main()
