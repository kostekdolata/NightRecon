"""Tests for deterministic professional engagement exports."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from nightrecon_shared_core.contracts import EngagementEnvelope
from nightrecon_red_engine.engagement_export import (
    build_engagement_report_export,
    write_engagement_report_export,
)
from nightrecon_red_engine.engagement_report import (
    build_engagement_professional_report,
)


class EngagementReportExportTests(unittest.TestCase):
    def test_export_fingerprint_is_deterministic(self):
        report = build_engagement_professional_report(
            EngagementEnvelope(engagement_id="eng-1", records=())
        )

        first = build_engagement_report_export(report)
        second = build_engagement_report_export(report)

        self.assertEqual(first.fingerprint_sha256, second.fingerprint_sha256)
        self.assertEqual(len(first.fingerprint_sha256), 64)

    def test_written_export_contains_version_and_fingerprint(self):
        report = build_engagement_professional_report(
            EngagementEnvelope(engagement_id="eng-1", records=())
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.json"
            result = write_engagement_report_export(report, path)
            payload = json.loads(path.read_text(encoding="utf-8"))
            if os.name != "nt":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(payload["fingerprint_sha256"], result.fingerprint_sha256)


if __name__ == "__main__":
    unittest.main()
