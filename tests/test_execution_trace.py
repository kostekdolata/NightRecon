"""Operator trace tests use only synthetic local audit files."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packages" / "red-night"))
from red_night_app.execution_trace import read_execution_trace


class ExecutionTraceTests(unittest.TestCase):
    def _read(self, events):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "audit.jsonl"
            path.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
            return read_execution_trace(audit_path=path, engagement_id="lab")

    def test_success_and_nonzero_exit_are_distinct(self):
        trace, warnings = self._read([
            dict(engagement_id="lab", action_id="a", command="python-version", status="started", recorded_at="t1"),
            dict(engagement_id="lab", action_id="b", command="scan", status="started", recorded_at="t2"),
            dict(engagement_id="lab", action_id="b", command="scan", status="completed", returncode=2, recorded_at="t3"),
            dict(engagement_id="lab", action_id="a", command="python-version", status="completed", returncode=0, recorded_at="t4"),
        ])
        self.assertEqual(warnings, ())
        self.assertEqual([t.status for t in trace], ["completed", "completed"])
        self.assertIn("succeeded", trace[0].describe())
        self.assertIn("failed", trace[1].describe())
        self.assertIn("exit=2", trace[1].describe())

    def test_cancellation_and_revocation_not_success(self):
        trace, _ = self._read([
            dict(engagement_id="lab", action_id="a", command="one", status="started"),
            dict(engagement_id="lab", action_id="a", command="one", status="revoked"),
            dict(engagement_id="lab", action_id="b", command="two", status="cancelled"),
        ])
        self.assertEqual([t.status for t in trace], ["revoked", "cancelled"])
        self.assertTrue(all("succeeded" not in t.describe() for t in trace))

    def test_incomplete_event_cannot_claim_running_or_success(self):
        trace, warnings = self._read([dict(engagement_id="lab", action_id="a", command="tool", status="started")])
        self.assertIn("started", trace[0].describe())
        self.assertTrue(any("unconfirmed" in w for w in warnings))

    def test_engagement_isolation_and_no_sensitive_output(self):
        trace, _ = self._read([
            dict(engagement_id="other", action_id="secret", command="private", status="completed", returncode=0),
            dict(engagement_id="lab", action_id="a", command="safe", status="completed", returncode=0, stdout="SECRET", arguments=["PASSWORD"]),
        ])
        self.assertEqual(len(trace), 1)
        self.assertNotIn("SECRET", trace[0].describe())
        self.assertNotIn("PASSWORD", trace[0].describe())
        self.assertNotIn("private", trace[0].describe())

    def test_contradictory_and_malformed_events_warn(self):
        trace, warnings = self._read([
            dict(engagement_id="lab", action_id="a", command="safe", status="started"),
            dict(engagement_id="lab", action_id="a", command="changed", status="completed", returncode=0),
        ])
        self.assertEqual(trace[0].status, "started")
        self.assertTrue(any("Malformed" in w for w in warnings))

    def test_missing_audit_is_empty_and_noncreating(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "missing.jsonl"
            self.assertEqual(read_execution_trace(audit_path=path, engagement_id="lab"), ((), ()))
            self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
