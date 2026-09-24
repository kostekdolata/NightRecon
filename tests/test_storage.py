"""Tests for NightRecon result storage."""

import json
import tempfile
import unittest
from pathlib import Path

from nightrecon.discovery_report import HostDiscoveryReport
from nightrecon.host_discovery import HostDiscoveryResult
from nightrecon.report import TcpScanReport
from nightrecon.session import ScanSession
from nightrecon.storage import ResultStore
from nightrecon.targets import parse_target
from nightrecon.tcp_scanner import TcpPortResult


class ResultStoreTests(unittest.TestCase):
    def test_session_is_saved_as_json(self):
        target = parse_target("127.0.0.1")
        session = ScanSession.create(
            target=target,
            scope_rules=("127.0.0.1",),
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            store = ResultStore(temp_dir)

            output_path = store.save_session(session)

            self.assertTrue(output_path.exists())
            self.assertEqual(
                output_path.name,
                f"{session.session_id}.json",
            )

    def test_saved_json_contains_session_data(self):
        target = parse_target("example.com")
        session = ScanSession.create(
            target=target,
            scope_rules=("example.com",),
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            store = ResultStore(temp_dir)

            output_path = store.save_session(session)

            with output_path.open("r", encoding="utf-8") as file:
                data = json.load(file)

            self.assertEqual(data["session_id"], session.session_id)
            self.assertEqual(data["target"], "example.com")
            self.assertEqual(data["target_type"], "hostname")
            self.assertEqual(data["scope"], ["example.com"])
            self.assertEqual(data["status"], "created")

    def test_results_directory_is_created_automatically(self):
        target = parse_target("10.0.0.1")
        session = ScanSession.create(
            target=target,
            scope_rules=("10.0.0.0/8",),
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            result_dir = Path(temp_dir) / "nested" / "results"
            store = ResultStore(result_dir)

            output_path = store.save_session(session)

            self.assertTrue(result_dir.exists())
            self.assertTrue(output_path.exists())

    def test_completed_report_is_saved(self):
        target = parse_target("127.0.0.1")
        session = ScanSession.create(
            target=target,
            scope_rules=("127.0.0.1",),
        )

        report = TcpScanReport.create(
            session=session,
            resolved_addresses=("127.0.0.1",),
            ports_requested=(80, 443),
            results=(
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
            ),
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            store = ResultStore(temp_dir)

            output_path = store.save_report(report)

            self.assertTrue(output_path.exists())
            self.assertEqual(
                output_path.name,
                f"{session.session_id}.json",
            )

    def test_saved_report_has_completed_status(self):
        target = parse_target("127.0.0.1")
        session = ScanSession.create(
            target=target,
            scope_rules=("127.0.0.1",),
        )

        report = TcpScanReport.create(
            session=session,
            resolved_addresses=("127.0.0.1",),
            ports_requested=(80,),
            results=(
                TcpPortResult(
                    address="127.0.0.1",
                    port=80,
                    is_open=True,
                    error_code=0,
                ),
            ),
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            store = ResultStore(temp_dir)

            output_path = store.save_report(report)

            with output_path.open("r", encoding="utf-8") as file:
                data = json.load(file)

            self.assertEqual(data["status"], "completed")
            self.assertEqual(data["ports_requested"], [80])
            self.assertEqual(
                data["resolved_addresses"],
                ["127.0.0.1"],
            )

    def test_discovery_report_is_saved(self):
        target = parse_target("192.0.2.0/30")
        session = ScanSession.create(
            target=target,
            scope_rules=("192.0.2.0/24",),
        )

        report = HostDiscoveryReport.create(
            session=session,
            ports_requested=(443,),
            max_hosts=8,
            results=(
                HostDiscoveryResult(
                    address="192.0.2.1",
                    responsive=True,
                    method="tcp-connect",
                    port=443,
                    observation="tcp-open",
                    error_code=0,
                ),
            ),
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            store = ResultStore(temp_dir)

            output_path = store.save_discovery_report(report)

            with output_path.open("r", encoding="utf-8") as file:
                data = json.load(file)

            self.assertEqual(data["target"], "192.0.2.0/30")
            self.assertEqual(
                data["summary"]["responsive_hosts"],
                1,
            )
            self.assertEqual(
                data["results"][0]["address"],
                "192.0.2.1",
            )

    def test_saved_report_contains_tcp_results(self):
        target = parse_target("127.0.0.1")
        session = ScanSession.create(
            target=target,
            scope_rules=("127.0.0.1",),
        )

        report = TcpScanReport.create(
            session=session,
            resolved_addresses=("127.0.0.1",),
            ports_requested=(80,),
            results=(
                TcpPortResult(
                    address="127.0.0.1",
                    port=80,
                    is_open=True,
                    error_code=0,
                ),
            ),
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            store = ResultStore(temp_dir)

            output_path = store.save_report(report)

            with output_path.open("r", encoding="utf-8") as file:
                data = json.load(file)

            self.assertEqual(len(data["results"]), 1)
            self.assertEqual(data["results"][0]["port"], 80)
            self.assertTrue(data["results"][0]["is_open"])
            self.assertEqual(data["results"][0]["error_code"], 0)


if __name__ == "__main__":
    unittest.main()
