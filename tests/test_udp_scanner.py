"""Tests for bounded Red Night UDP scanning primitives."""

import errno
import socket
import unittest
from unittest.mock import MagicMock, patch

from nightrecon_red_engine.udp_scanner import (
    MAX_UDP_PORTS_PER_SCAN,
    MAX_UDP_PROBE_BYTES,
    MAX_UDP_RETRIES,
    MAX_UDP_ATTEMPTS_PER_SCAN,
    UdpPortResult,
    UdpScanSummary,
    identify_udp_service,
    udp_probe_payload_for_port,
    validate_udp_response,
    scan_udp_port,
    scan_udp_ports,
    summarize_udp_results,
)


class UdpScannerTests(unittest.TestCase):
    def test_udp_summary_is_deterministic_and_non_networking(self):
        results = (
            UdpPortResult(
                address="192.0.2.10",
                port=53,
                state="open",
                service_hint="dns",
                protocol_match=True,
                attempts=2,
            ),
            UdpPortResult(
                address="192.0.2.10",
                port=123,
                state="open|filtered",
                service_hint="ntp",
                attempts=3,
            ),
            UdpPortResult(
                address="192.0.2.10",
                port=161,
                state="closed",
                service_hint="snmp",
                attempts=1,
            ),
            UdpPortResult(
                address="192.0.2.10",
                port=65000,
                state="error",
                service_hint="unknown",
                attempts=1,
            ),
        )

        summary = summarize_udp_results(results)

        self.assertEqual(
            summary,
            UdpScanSummary(
                total_results=4,
                total_attempts=7,
                open_count=1,
                open_filtered_count=1,
                closed_count=1,
                error_count=1,
                protocol_confirmed_count=1,
                service_hint_counts=(
                    ("dns", 1),
                    ("ntp", 1),
                    ("snmp", 1),
                    ("unknown", 1),
                ),
            ),
        )

    def test_udp_summary_rejects_invalid_state_and_attempt_count(self):
        with self.assertRaisesRegex(
            ValueError,
            "Unsupported UDP result state",
        ):
            summarize_udp_results(
                (
                    UdpPortResult(
                        address="192.0.2.10",
                        port=53,
                        state="unexpected",
                    ),
                )
            )

        with self.assertRaisesRegex(
            ValueError,
            "attempts must be at least 1",
        ):
            summarize_udp_results(
                (
                    UdpPortResult(
                        address="192.0.2.10",
                        port=53,
                        state="open",
                        attempts=0,
                    ),
                )
            )

    def test_timeout_retry_can_recover_with_positive_response(self):
        fake_socket = MagicMock()
        response = bytearray(12)
        response[2] = 0x80
        fake_socket.recv.side_effect = [
            socket.timeout(),
            bytes(response),
        ]

        with patch(
            "nightrecon_red_engine.udp_scanner.socket.socket",
            return_value=fake_socket,
        ):
            result = scan_udp_port(
                "192.0.2.10",
                53,
                0.25,
                retries=1,
            )

        self.assertEqual(result.state, "open")
        self.assertEqual(result.attempts, 2)
        self.assertEqual(fake_socket.send.call_count, 2)

    def test_exhausted_retries_preserve_open_filtered_uncertainty(self):
        fake_socket = MagicMock()
        fake_socket.recv.side_effect = socket.timeout()

        with patch(
            "nightrecon_red_engine.udp_scanner.socket.socket",
            return_value=fake_socket,
        ):
            result = scan_udp_port(
                "192.0.2.10",
                161,
                0.25,
                retries=MAX_UDP_RETRIES,
            )

        self.assertEqual(result.state, "open|filtered")
        self.assertEqual(result.attempts, MAX_UDP_RETRIES + 1)
        self.assertIn(
            f"{MAX_UDP_RETRIES + 1} attempts",
            result.evidence,
        )

    def test_probe_profiles_are_small_and_service_specific(self):
        dns_payload = udp_probe_payload_for_port(53)
        ntp_payload = udp_probe_payload_for_port(123)

        self.assertGreater(len(dns_payload), 0)
        self.assertGreater(len(ntp_payload), 0)
        self.assertLessEqual(len(dns_payload), MAX_UDP_PROBE_BYTES)
        self.assertLessEqual(len(ntp_payload), MAX_UDP_PROBE_BYTES)
        self.assertEqual(udp_probe_payload_for_port(161), b"")

    def test_default_scan_uses_defined_service_probe_profile(self):
        fake_socket = MagicMock()
        fake_socket.recv.return_value = b"reply"

        with patch(
            "nightrecon_red_engine.udp_scanner.socket.socket",
            return_value=fake_socket,
        ):
            scan_udp_port(
                "192.0.2.10",
                123,
                0.5,
            )

        fake_socket.send.assert_called_once_with(
            udp_probe_payload_for_port(123)
        )

    def test_common_udp_service_hints_are_deterministic(self):
        self.assertEqual(identify_udp_service(53), "dns")
        self.assertEqual(identify_udp_service(123), "ntp")
        self.assertEqual(identify_udp_service(161), "snmp")
        self.assertEqual(identify_udp_service(65000), "unknown")

    def test_dns_and_ntp_response_validation_is_structural(self):
        dns_response = bytearray(12)
        dns_response[2] = 0x80
        self.assertEqual(
            validate_udp_response(53, bytes(dns_response)),
            (True, "DNS QR response bit set"),
        )
        self.assertEqual(
            validate_udp_response(53, b"short"),
            (False, "DNS response shorter than 12-byte header"),
        )

        ntp_response = bytearray(48)
        ntp_response[0] = 0x24
        matched, evidence = validate_udp_response(
            123,
            bytes(ntp_response),
        )
        self.assertTrue(matched)
        self.assertIn("server/broadcast", evidence)

        self.assertEqual(
            validate_udp_response(161, b"anything"),
            (None, "no protocol response validator defined"),
        )

    def test_protocol_consistent_dns_reply_gets_high_confidence(self):
        fake_socket = MagicMock()
        response = bytearray(12)
        response[2] = 0x80
        fake_socket.recv.return_value = bytes(response)

        with patch(
            "nightrecon_red_engine.udp_scanner.socket.socket",
            return_value=fake_socket,
        ):
            result = scan_udp_port(
                "192.0.2.10",
                53,
                0.5,
            )

        self.assertEqual(result.state, "open")
        self.assertTrue(result.protocol_match)
        self.assertEqual(result.confidence, "high")
        self.assertIn("DNS QR response bit set", result.evidence)

    def test_response_is_positive_open_evidence(self):
        fake_socket = MagicMock()
        fake_socket.recv.return_value = b"reply"

        with patch(
            "nightrecon_red_engine.udp_scanner.socket.socket",
            return_value=fake_socket,
        ) as socket_factory:
            result = scan_udp_port(
                "192.0.2.10",
                53,
                0.5,
                payload=b"probe",
            )

        self.assertEqual(
            result,
            UdpPortResult(
                address="192.0.2.10",
                port=53,
                state="open",
                response_size=5,
                error_code=0,
                service_hint="dns",
                confidence="medium",
                evidence=(
                    "received 5 UDP response bytes; "
                    "DNS response shorter than 12-byte header"
                ),
                protocol_match=False,
                attempts=1,
            ),
        )
        self.assertTrue(result.is_open)
        socket_factory.assert_called_once_with(
            socket.AF_INET,
            socket.SOCK_DGRAM,
        )
        fake_socket.connect.assert_called_once_with(
            ("192.0.2.10", 53)
        )
        fake_socket.send.assert_called_once_with(b"probe")
        fake_socket.recv.assert_called_once_with(MAX_UDP_PROBE_BYTES)
        fake_socket.close.assert_called_once()

    def test_timeout_preserves_open_filtered_uncertainty(self):
        fake_socket = MagicMock()
        fake_socket.recv.side_effect = socket.timeout()

        with patch(
            "nightrecon_red_engine.udp_scanner.socket.socket",
            return_value=fake_socket,
        ):
            result = scan_udp_port(
                "192.0.2.10",
                161,
                0.25,
            )

        self.assertEqual(result.state, "open|filtered")
        self.assertFalse(result.is_open)
        self.assertIsNone(result.error_code)
        self.assertEqual(result.service_hint, "snmp")
        self.assertEqual(result.confidence, "low")
        self.assertIn("unresolved", result.evidence)

    def test_icmp_unreachable_style_error_marks_port_closed(self):
        fake_socket = MagicMock()
        fake_socket.recv.side_effect = ConnectionRefusedError(
            errno.ECONNREFUSED,
            "Connection refused",
        )

        with patch(
            "nightrecon_red_engine.udp_scanner.socket.socket",
            return_value=fake_socket,
        ):
            result = scan_udp_port(
                "192.0.2.10",
                9999,
                0.25,
            )

        self.assertEqual(result.state, "closed")
        self.assertEqual(result.error_code, errno.ECONNREFUSED)
        self.assertEqual(result.confidence, "high")
        self.assertIn("socket refusal", result.evidence)

    def test_unclassified_socket_error_is_not_misreported_closed(self):
        fake_socket = MagicMock()
        fake_socket.recv.side_effect = OSError(
            errno.ENETUNREACH,
            "Network unreachable",
        )

        with patch(
            "nightrecon_red_engine.udp_scanner.socket.socket",
            return_value=fake_socket,
        ):
            result = scan_udp_port(
                "192.0.2.10",
                9999,
                0.25,
            )

        self.assertEqual(result.state, "error")
        self.assertEqual(result.error_code, errno.ENETUNREACH)
        self.assertEqual(result.confidence, "low")
        self.assertIn("socket error code", result.evidence)

    def test_ipv6_uses_ipv6_datagram_socket(self):
        fake_socket = MagicMock()
        fake_socket.recv.return_value = b"x"

        with patch(
            "nightrecon_red_engine.udp_scanner.socket.socket",
            return_value=fake_socket,
        ) as socket_factory:
            result = scan_udp_port(
                "2001:db8::10",
                53,
                0.5,
            )

        self.assertEqual(result.state, "open")
        socket_factory.assert_called_once_with(
            socket.AF_INET6,
            socket.SOCK_DGRAM,
        )
        fake_socket.connect.assert_called_once_with(
            ("2001:db8::10", 53, 0, 0)
        )

    def test_multi_port_results_are_deterministically_sorted(self):
        def fake_scan(address, port, timeout, *, payload=b"", retries=0):
            states = {
                53: "open",
                123: "open|filtered",
                161: "closed",
            }
            return UdpPortResult(
                address=address,
                port=port,
                state=states[port],
            )

        with patch(
            "nightrecon_red_engine.udp_scanner.scan_udp_port",
            side_effect=fake_scan,
        ):
            results = scan_udp_ports(
                "192.0.2.10",
                (161, 53, 123),
                0.5,
                max_workers=3,
            )

        self.assertEqual(
            tuple(result.port for result in results),
            (53, 123, 161),
        )
        self.assertEqual(
            tuple(result.state for result in results),
            ("open", "open|filtered", "closed"),
        )

    def test_duplicate_ports_are_rejected_before_network_use(self):
        with patch(
            "nightrecon_red_engine.udp_scanner.scan_udp_port"
        ) as scan_port:
            with self.assertRaisesRegex(
                ValueError,
                "must not contain duplicates",
            ):
                scan_udp_ports(
                    "192.0.2.10",
                    (53, 53),
                    0.5,
                )

        scan_port.assert_not_called()

    def test_attempt_budget_accounts_for_retries(self):
        port_count = (MAX_UDP_ATTEMPTS_PER_SCAN // 2) + 1
        ports = tuple(range(1, port_count + 1))

        with self.assertRaisesRegex(
            ValueError,
            "UDP attempt budget exceeds",
        ):
            scan_udp_ports(
                "192.0.2.10",
                ports,
                0.5,
                retries=1,
            )

    def test_attempt_budget_allows_bounded_configuration(self):
        port_count = MAX_UDP_ATTEMPTS_PER_SCAN // 2
        ports = tuple(range(1, port_count + 1))

        def fake_scan(
            address,
            port,
            timeout,
            *,
            payload=None,
            retries=0,
        ):
            return UdpPortResult(
                address=address,
                port=port,
                state="open|filtered",
            )

        with patch(
            "nightrecon_red_engine.udp_scanner.scan_udp_port",
            side_effect=fake_scan,
        ):
            results = scan_udp_ports(
                "192.0.2.10",
                ports,
                0.5,
                retries=1,
                max_workers=8,
            )

        self.assertEqual(len(results), port_count)

    def test_port_count_budget_is_enforced(self):
        ports = tuple(range(1, MAX_UDP_PORTS_PER_SCAN + 2))

        with self.assertRaisesRegex(
            ValueError,
            "UDP port count exceeds",
        ):
            scan_udp_ports(
                "192.0.2.10",
                ports,
                0.5,
            )

    def test_probe_payload_budget_is_enforced(self):
        payload = b"x" * (MAX_UDP_PROBE_BYTES + 1)

        with self.assertRaisesRegex(
            ValueError,
            "UDP payload exceeds",
        ):
            scan_udp_port(
                "192.0.2.10",
                53,
                0.5,
                payload=payload,
            )

    def test_invalid_inputs_fail_before_network_use(self):
        with patch(
            "nightrecon_red_engine.udp_scanner.socket.socket"
        ) as socket_factory:
            with self.assertRaises(ValueError):
                scan_udp_port("not-an-ip", 53, 0.5)

            with self.assertRaises(ValueError):
                scan_udp_port("192.0.2.10", 0, 0.5)

            with self.assertRaises(ValueError):
                scan_udp_port("192.0.2.10", 53, 0)

            with self.assertRaises(ValueError):
                scan_udp_ports(
                    "192.0.2.10",
                    (),
                    0.5,
                )

            with self.assertRaises(ValueError):
                scan_udp_ports(
                    "192.0.2.10",
                    (53,),
                    0.5,
                    max_workers=0,
                )

            with self.assertRaises(ValueError):
                scan_udp_port(
                    "192.0.2.10",
                    53,
                    0.5,
                    retries=MAX_UDP_RETRIES + 1,
                )

        socket_factory.assert_not_called()


if __name__ == "__main__":
    unittest.main()
