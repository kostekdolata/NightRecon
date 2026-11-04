"""Concurrent known-tool orchestration regressions; no subprocess or network."""
import json
import subprocess
import threading
import time
import unittest
from unittest.mock import patch

from nightrecon_red_engine.governed_assessment_batch import (
    GovernedAssessmentTask, run_governed_assessment_batch,
)


class FakeOutcome:
    def __init__(self, tool):
        self.tool = tool
    def operator_report(self):
        return {"tool": self.tool, "execution_status": "succeeded",
                "evidence_status": "unverified-observation"}


class GovernedAssessmentBatchTests(unittest.TestCase):
    def task(self, kind, target, action):
        return GovernedAssessmentTask(
            kind=kind, engagement_id="lab", action_id=action, target=target,
            executable="/trusted/" + kind, trusted_sha256="a" * 64,
            audit_path="/unused/auth.jsonl", result_audit_path="/unused/results.jsonl",
            capture_root="/unused/captures" if kind == "tshark" else None,
            capture_path="/unused/captures/sample.pcap" if kind == "tshark" else None,
        )

    def test_independent_known_tools_really_overlap_and_return_both_reports(self):
        barrier = threading.Barrier(2, timeout=3)
        observed = []
        def run_tool(**kwargs):
            observed.append(kwargs)
            barrier.wait()
            return FakeOutcome("nmap" if kwargs["target"] == "192.0.2.1" else "tshark")
        with patch(
            "nightrecon_red_engine.governed_assessment_batch.execute_governed_nmap_discovery",
            side_effect=run_tool,
        ), patch(
            "nightrecon_red_engine.governed_assessment_batch.execute_governed_tshark_inspection",
            side_effect=run_tool,
        ):
            report = run_governed_assessment_batch(
                authority=None, enabled=True, max_workers=2,
                tasks=(self.task("nmap", "192.0.2.1", "one"),
                       self.task("tshark", "192.0.2.2", "two")),
            )
        self.assertEqual([x.status for x in report.tasks], ["succeeded", "succeeded"])
        self.assertEqual(len(observed), 2)
        self.assertTrue(all(x["enabled"] for x in observed))
        self.assertTrue(all(hasattr(x["cancel_event"], "is_set") for x in observed))
        self.assertEqual(report.operator_report()["summary"]["succeeded"], 2)
        self.assertEqual(sum(e.status == "running" for e in report.events), 2)

    def test_same_target_serialised_even_with_two_workers(self):
        guard = threading.Lock()
        active, peak = [0], [0]
        def run_tool(**kwargs):
            with guard:
                active[0] += 1
                peak[0] = max(peak[0], active[0])
            time.sleep(0.03)
            with guard:
                active[0] -= 1
            return FakeOutcome("nmap")
        with patch(
            "nightrecon_red_engine.governed_assessment_batch.execute_governed_nmap_discovery",
            side_effect=run_tool,
        ):
            report = run_governed_assessment_batch(
                authority=None, enabled=True, max_workers=2,
                tasks=(self.task("nmap", "192.0.2.1", "one"),
                       self.task("nmap", "192.0.2.1", "two")),
            )
        self.assertEqual(peak[0], 1)
        self.assertEqual(report.operator_report()["summary"]["succeeded"], 2)

    def test_nuclei_and_nmap_run_independently_with_approved_adapters(self):
        barrier = threading.Barrier(2, timeout=3)
        seen = []
        def nmap(**kwargs):
            seen.append(("nmap", kwargs))
            barrier.wait()
            return FakeOutcome("nmap")
        def nuclei(**kwargs):
            seen.append(("nuclei", kwargs))
            barrier.wait()
            return FakeOutcome("nuclei")
        with patch(
            "nightrecon_red_engine.governed_assessment_batch.execute_governed_nmap_discovery",
            side_effect=nmap,
        ), patch(
            "nightrecon_red_engine.governed_assessment_batch.execute_governed_nuclei_fingerprint",
            side_effect=nuclei,
        ):
            result = run_governed_assessment_batch(
                authority=None, enabled=True, max_workers=2,
                tasks=(self.task("nmap", "192.0.2.1", "scan-one"),
                       self.task("nuclei", "http://192.0.2.2:8080", "fingerprint-two")),
            )
        self.assertEqual([item.status for item in result.tasks], ["succeeded", "succeeded"])
        params = dict(seen)
        self.assertEqual(params["nuclei"]["target_url"], "http://192.0.2.2:8080")
        self.assertNotIn("target", params["nuclei"])
        self.assertIs(params["nmap"]["cancel_event"], params["nuclei"]["cancel_event"])
        self.assertTrue(params["nuclei"]["enabled"])

    def test_nuclei_url_and_nmap_same_host_are_serialised(self):
        guard = threading.Lock()
        active, peak = [0], [0]
        def run_tool(**kwargs):
            with guard:
                active[0] += 1
                peak[0] = max(peak[0], active[0])
            time.sleep(0.025)
            with guard:
                active[0] -= 1
            return FakeOutcome("tool")
        with patch(
            "nightrecon_red_engine.governed_assessment_batch.execute_governed_nmap_discovery",
            side_effect=run_tool,
        ), patch(
            "nightrecon_red_engine.governed_assessment_batch.execute_governed_nuclei_fingerprint",
            side_effect=run_tool,
        ):
            result = run_governed_assessment_batch(
                authority=None, enabled=True, max_workers=2,
                tasks=(self.task("nmap", "192.0.2.1", "scan-one"),
                       self.task("nuclei", "http://192.0.2.1:8080", "fingerprint-two")),
            )
        self.assertEqual(peak[0], 1)
        self.assertEqual(result.operator_report()["summary"]["succeeded"], 2)

    def test_nuclei_cannot_receive_capture_parameters(self):
        nuclei = self.task("nuclei", "http://192.0.2.1", "one")
        from dataclasses import replace
        with self.assertRaisesRegex(ValueError, "capture"):
            run_governed_assessment_batch(
                authority=None, enabled=True,
                tasks=(replace(nuclei, capture_path="/tmp/capture.pcap"),),
            )

    def test_permission_denial_keeps_independent_success(self):
        def run_nmap(**kwargs):
            raise PermissionError("sensitive-details-must-not-appear")
        with patch(
            "nightrecon_red_engine.governed_assessment_batch.execute_governed_nmap_discovery",
            side_effect=run_nmap,
        ), patch(
            "nightrecon_red_engine.governed_assessment_batch.execute_governed_tshark_inspection",
            return_value=FakeOutcome("tshark"),
        ):
            result = run_governed_assessment_batch(
                authority=None, enabled=True,
                tasks=(self.task("nmap", "192.0.2.1", "one"),
                       self.task("tshark", "192.0.2.2", "two")),
            )
        self.assertEqual([x.status for x in result.tasks], ["blocked", "succeeded"])
        self.assertNotIn("sensitive-details-must-not-appear", json.dumps(result.operator_report()))

    def test_cancellation_before_start_prevents_all_work(self):
        stopped = threading.Event()
        stopped.set()
        with patch(
            "nightrecon_red_engine.governed_assessment_batch.execute_governed_nmap_discovery",
        ) as run:
            result = run_governed_assessment_batch(
                authority=None, enabled=True, cancel_event=stopped,
                tasks=(self.task("nmap", "192.0.2.1", "one"),),
            )
            run.assert_not_called()
        self.assertEqual(result.tasks[0].status, "cancelled")

    def test_timeout_is_reported_without_stdout_or_secret(self):
        with patch(
            "nightrecon_red_engine.governed_assessment_batch.execute_governed_nmap_discovery",
            side_effect=subprocess.TimeoutExpired("secret-command", 30),
        ):
            result = run_governed_assessment_batch(
                authority=None, enabled=True,
                tasks=(self.task("nmap", "192.0.2.1", "one"),),
            )
        self.assertEqual(result.tasks[0].status, "timed-out")
        self.assertNotIn("secret-command", json.dumps(result.operator_report()))

    def test_batch_validation_is_fail_closed(self):
        task = self.task("nmap", "192.0.2.1", "one")
        with self.assertRaises(PermissionError):
            run_governed_assessment_batch(authority=None, tasks=(task,))
        with self.assertRaises(ValueError):
            run_governed_assessment_batch(authority=None, enabled=True, tasks=(task, task))
        with self.assertRaises(ValueError):
            run_governed_assessment_batch(authority=None, enabled=True,
                                          max_workers=99, tasks=(task,))
        with self.assertRaises(ValueError):
            run_governed_assessment_batch(authority=None, enabled=True, tasks=(
                self.task("arbitrary-shell", "192.0.2.1", "bad"),
            ))

    def test_existing_offline_tshark_receives_cancellation(self):
        # Verify that the coordinator signature continues to forward the
        # same cancellation token to the atomic command runner.
        from nightrecon_red_engine.governed_tshark_coordinator import (
            execute_governed_tshark_inspection,
        )
        import hashlib
        import tempfile
        from pathlib import Path
        from nightrecon_red_engine.governed_command_runner import CommandOutcome
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tool = root / "tshark"
            tool.write_bytes(b"fixture")
            capture = root / "capture.pcap"
            capture.write_bytes(b"fixture")
            token = threading.Event()
            with patch(
                "nightrecon_red_engine.governed_tshark_coordinator.execute_atomically_governed",
                return_value=CommandOutcome("tshark-bounded-offline", 0, "[]", ""),
            ) as execute:
                execute_governed_tshark_inspection(
                    authority=None, engagement_id="lab", action_id="one",
                    target="192.0.2.1", executable=tool,
                    trusted_sha256=hashlib.sha256(tool.read_bytes()).hexdigest(),
                    capture_path=capture, capture_root=root,
                    audit_path=root / "audit", result_audit_path=root / "results",
                    enabled=True, cancel_event=token,
                )
                self.assertIs(execute.call_args.kwargs["cancel_event"], token)


if __name__ == "__main__":
    unittest.main()
