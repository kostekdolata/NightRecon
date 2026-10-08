"""Tests for the NightRecon TCP scanner."""

import errno
import socket
import unittest
from unittest.mock import MagicMock, patch

from nightrecon.tcp_scanner import (
    MAX_TCP_ATTEMPTS_PER_SCAN,
    MAX_TCP_PORTS_PER_SCAN,
    MAX_TCP_RETRIES,
    MAX_TCP_WORKERS,
    TcpPortResult,
    TcpScanSummary,
    scan_tcp_port,
    scan_tcp_ports,
    summarize_tcp_results,
)
from nightrecon import red_tcp_scanner


class TcpScannerTests(unittest.TestCase):
    def test_legacy_module_reexports_red_engine(self):
        self.assertIs(TcpPortResult, red_tcp_scanner.TcpPortResult)
        self.assertIs(TcpScanSummary, red_tcp_scanner.TcpScanSummary)
        self.assertIs(scan_tcp_port, red_tcp_scanner.scan_tcp_port)
        self.assertIs(scan_tcp_ports, red_tcp_scanner.scan_tcp_ports)
        self.assertIs(
            summarize_tcp_results,
            red_tcp_scanner.summarize_tcp_results,
        )

    def test_open_ipv4_port(self):
        fake_socket = MagicMock()
        fake_socket.connect_ex.return_value = 0

        with patch(
            "nightrecon.tcp_scanner.socket.socket",
            return_value=fake_socket,
        ) as socket_factory:
            result = scan_tcp_port("127.0.0.1", 443, 2.0)

        self.assertTrue(result.is_open)
        self.assertEqual(result.address, "127.0.0.1")
        self.assertEqual(result.port, 443)
        self.assertEqual(result.error_code, 0)
        self.assertEqual(result.state, "open")
        self.assertEqual(result.confidence, "high")
        self.assertEqual(result.attempts, 1)
        self.assertIn("completed successfully", result.evidence)
        socket_factory.assert_called_once_with(
            socket.AF_INET,
            socket.SOCK_STREAM,
        )
        fake_socket.settimeout.assert_called_once_with(2.0)
        fake_socket.connect_ex.assert_called_once_with(
            ("127.0.0.1", 443)
        )
        fake_socket.close.assert_called_once()

    def test_closed_ipv4_port(self):
        fake_socket = MagicMock()
        fake_socket.connect_ex.return_value = 10061

        with patch(
            "nightrecon.tcp_scanner.socket.socket",
            return_value=fake_socket,
        ):
            result = scan_tcp_port("127.0.0.1", 80, 2.0)

        self.assertFalse(result.is_open)
        self.assertEqual(result.error_code, 10061)
        self.assertEqual(result.state, "closed")
        self.assertEqual(result.confidence, "high")
        fake_socket.close.assert_called_once()

    def test_timeout_is_filtered_and_retryable(self):
        timeout_code = getattr(errno, "WSAETIMEDOUT", 10060)
        first_socket = MagicMock()
        first_socket.connect_ex.return_value = timeout_code
        second_socket = MagicMock()
        second_socket.connect_ex.return_value = 0

        with patch(
            "nightrecon.tcp_scanner.socket.socket",
            side_effect=(first_socket, second_socket),
        ):
            result = scan_tcp_port(
                "127.0.0.1",
                443,
                0.25,
                retries=1,
            )

        self.assertTrue(result.is_open)
        self.assertEqual(result.state, "open")
        self.assertEqual(result.attempts, 2)
        first_socket.close.assert_called_once()
        second_socket.close.assert_called_once()

    def test_exhausted_timeouts_preserve_filtered_state(self):
        timeout_code = getattr(errno, "WSAETIMEDOUT", 10060)
        sockets = tuple(
            MagicMock()
            for _ in range(MAX_TCP_RETRIES + 1)
        )
        for fake_socket in sockets:
            fake_socket.connect_ex.return_value = timeout_code

        with patch(
            "nightrecon.tcp_scanner.socket.socket",
            side_effect=sockets,
        ):
            result = scan_tcp_port(
                "127.0.0.1",
                443,
                0.25,
                retries=MAX_TCP_RETRIES,
            )

        self.assertFalse(result.is_open)
        self.assertEqual(result.state, "filtered")
        self.assertEqual(result.attempts, MAX_TCP_RETRIES + 1)
        self.assertIn(
            f"{MAX_TCP_RETRIES + 1} attempts",
            result.evidence,
        )

    def test_socket_timeout_exception_is_filtered(self):
        fake_socket = MagicMock()
        fake_socket.connect_ex.side_effect = socket.timeout()

        with patch(
            "nightrecon.tcp_scanner.socket.socket",
            return_value=fake_socket,
        ):
            result = scan_tcp_port("127.0.0.1", 443, 0.25)

        self.assertEqual(result.state, "filtered")
        self.assertEqual(result.confidence, "medium")

    def test_unclassified_socket_error_is_error(self):
        fake_socket = MagicMock()
        fake_socket.connect_ex.side_effect = OSError(
            errno.ENETUNREACH,
            "Network unreachable",
        )

        with patch(
            "nightrecon.tcp_scanner.socket.socket",
            return_value=fake_socket,
        ):
            result = scan_tcp_port("127.0.0.1", 443, 0.25)

        self.assertFalse(result.is_open)
        self.assertEqual(result.state, "error")
        self.assertEqual(result.error_code, errno.ENETUNREACH)
        self.assertEqual(result.confidence, "low")

    def test_ipv6_uses_ipv6_socket(self):
        fake_socket = MagicMock()
        fake_socket.connect_ex.return_value = 0

        with patch(
            "nightrecon.tcp_scanner.socket.socket",
            return_value=fake_socket,
        ) as socket_factory:
            result = scan_tcp_port("::1", 443, 1.0)

        self.assertTrue(result.is_open)
        socket_factory.assert_called_once_with(
            socket.AF_INET6,
            socket.SOCK_STREAM,
        )
        fake_socket.connect_ex.assert_called_once_with(
            ("::1", 443, 0, 0)
        )

    def test_multiple_ports_are_scanned_and_sorted(self):
        def fake_scan(address, port, timeout):
            return TcpPortResult(
                address=address,
                port=port,
                is_open=port == 443,
                error_code=0 if port == 443 else 10061,
                state="open" if port == 443 else "closed",
            )

        with patch(
            "nightrecon.tcp_scanner.scan_tcp_port",
            side_effect=fake_scan,
        ) as scan_port:
            results = scan_tcp_ports(
                "127.0.0.1",
                (443, 22, 80),
                2.0,
                max_workers=3,
            )

        self.assertEqual(
            tuple(result.port for result in results),
            (22, 80, 443),
        )
        self.assertFalse(results[0].is_open)
        self.assertFalse(results[1].is_open)
        self.assertTrue(results[2].is_open)
        self.assertEqual(scan_port.call_count, 3)

    def test_multi_port_retries_are_forwarded_when_requested(self):
        def fake_scan(address, port, timeout, *, retries=0):
            return TcpPortResult(
                address=address,
                port=port,
                is_open=False,
                error_code=10060,
                state="filtered",
                confidence="medium",
                attempts=retries + 1,
            )

        with patch(
            "nightrecon.tcp_scanner.scan_tcp_port",
            side_effect=fake_scan,
        ) as scan_port:
            results = scan_tcp_ports(
                "127.0.0.1",
                (80, 443),
                0.25,
                max_workers=2,
                retries=1,
            )

        self.assertEqual(len(results), 2)
        self.assertEqual(scan_port.call_count, 2)
        for call in scan_port.call_args_list:
            self.assertEqual(call.kwargs["retries"], 1)

    def test_socket_error_does_not_abort_multi_port_scan(self):
        def fake_scan(address, port, timeout):
            if port == 80:
                raise OSError(10051, "Network is unreachable")

            return TcpPortResult(
                address=address,
                port=port,
                is_open=True,
                error_code=0,
                state="open",
                confidence="high",
            )

        with patch(
            "nightrecon.tcp_scanner.scan_tcp_port",
            side_effect=fake_scan,
        ):
            results = scan_tcp_ports(
                "127.0.0.1",
                (80, 443),
                2.0,
                max_workers=2,
            )

        self.assertEqual(
            tuple(result.port for result in results),
            (80, 443),
        )
        self.assertFalse(results[0].is_open)
        self.assertEqual(results[0].error_code, 10051)
        self.assertEqual(results[0].state, "error")
        self.assertTrue(results[1].is_open)
        self.assertEqual(results[1].error_code, 0)

    def test_summary_is_deterministic(self):
        results = (
            TcpPortResult(
                address="192.0.2.10",
                port=22,
                is_open=True,
                error_code=0,
                state="open",
                attempts=1,
            ),
            TcpPortResult(
                address="192.0.2.10",
                port=80,
                is_open=False,
                error_code=10061,
                state="closed",
                attempts=1,
            ),
            TcpPortResult(
                address="192.0.2.10",
                port=443,
                is_open=False,
                error_code=10060,
                state="filtered",
                attempts=2,
            ),
            TcpPortResult(
                address="192.0.2.10",
                port=8080,
                is_open=False,
                error_code=10051,
                state="error",
                attempts=1,
            ),
        )

        self.assertEqual(
            summarize_tcp_results(results),
            TcpScanSummary(
                total_results=4,
                total_attempts=5,
                open_count=1,
                closed_count=1,
                filtered_count=1,
                error_count=1,
            ),
        )

    def test_summary_rejects_invalid_state_and_attempt_count(self):
        with self.assertRaisesRegex(
            ValueError,
            "Unsupported TCP result state",
        ):
            summarize_tcp_results(
                (
                    TcpPortResult(
                        address="192.0.2.10",
                        port=80,
                        is_open=False,
                        error_code=1,
                        state="unexpected",
                    ),
                )
            )

        with self.assertRaisesRegex(
            ValueError,
            "attempts must be at least 1",
        ):
            summarize_tcp_results(
                (
                    TcpPortResult(
                        address="192.0.2.10",
                        port=80,
                        is_open=False,
                        error_code=1,
                        state="error",
                        attempts=0,
                    ),
                )
            )

    def test_duplicate_ports_are_rejected_before_network_use(self):
        with patch(
            "nightrecon.tcp_scanner.scan_tcp_port"
        ) as scan_port:
            with self.assertRaisesRegex(
                ValueError,
                "must not contain duplicates",
            ):
                scan_tcp_ports(
                    "127.0.0.1",
                    (80, 80),
                    0.5,
                )

        scan_port.assert_not_called()

    def test_port_count_budget_is_enforced(self):
        ports = tuple(range(1, MAX_TCP_PORTS_PER_SCAN + 2))

        with self.assertRaisesRegex(
            ValueError,
            "TCP port count exceeds",
        ):
            scan_tcp_ports("127.0.0.1", ports, 0.5)

    def test_attempt_budget_accounts_for_retries(self):
        port_count = (MAX_TCP_ATTEMPTS_PER_SCAN // 3) + 1
        ports = tuple(range(1, port_count + 1))

        with self.assertRaisesRegex(
            ValueError,
            "TCP attempt budget exceeds",
        ):
            scan_tcp_ports(
                "127.0.0.1",
                ports,
                0.5,
                retries=2,
            )

    def test_worker_limit_is_enforced(self):
        with self.assertRaisesRegex(
            ValueError,
            "max_workers must be between",
        ):
            scan_tcp_ports(
                "127.0.0.1",
                (80,),
                0.5,
                max_workers=MAX_TCP_WORKERS + 1,
            )

    def test_invalid_ip_is_rejected(self):
        with self.assertRaises(ValueError):
            scan_tcp_port("not-an-ip", 443, 2.0)

    def test_port_zero_is_rejected(self):
        with self.assertRaises(ValueError):
            scan_tcp_port("127.0.0.1", 0, 2.0)

    def test_port_above_65535_is_rejected(self):
        with self.assertRaises(ValueError):
            scan_tcp_port("127.0.0.1", 65536, 2.0)

    def test_invalid_timeout_is_rejected(self):
        with self.assertRaises(ValueError):
            scan_tcp_port("127.0.0.1", 443, 0)

    def test_empty_port_collection_is_rejected(self):
        with self.assertRaises(ValueError):
            scan_tcp_ports("127.0.0.1", (), 2.0)

    def test_invalid_worker_count_is_rejected(self):
        with self.assertRaises(ValueError):
            scan_tcp_ports(
                "127.0.0.1",
                (80,),
                2.0,
                max_workers=0,
            )

    def test_invalid_retry_count_is_rejected_before_network_use(self):
        with patch(
            "nightrecon.tcp_scanner.socket.socket"
        ) as socket_factory:
            with self.assertRaises(ValueError):
                scan_tcp_port(
                    "127.0.0.1",
                    443,
                    0.5,
                    retries=MAX_TCP_RETRIES + 1,
                )

        socket_factory.assert_not_called()


if __name__ == "__main__":
    unittest.main()
