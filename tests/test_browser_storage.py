"""Tests for separate browser-discovery result persistence."""

import json
import tempfile
import unittest

from nightrecon.browser_playwright import PlaywrightDiscoveryResult
from nightrecon.browser_policy import (
    BrowserDiscoveryPolicy,
    BrowserWorkerState,
)
from nightrecon.browser_report import BrowserDiscoveryReport
from nightrecon.browser_worker import BrowserDiscoverySnapshot
from nightrecon.session import ScanSession
from nightrecon.storage import ResultStore
from nightrecon.targets import parse_target


class BrowserStorageTests(unittest.TestCase):
    def test_browser_report_is_saved_separately_from_crawl_session_file(self):
        session = ScanSession.create(
            target=parse_target("example.test"),
            scope_rules=("example.test",),
        )
        policy = BrowserDiscoveryPolicy(
            origin="https://example.test",
        )
        snapshot = BrowserDiscoverySnapshot(
            origin=policy.origin,
            state=BrowserWorkerState(
                requests_used=0,
                pages_used=0,
                runtime_seconds=0.0,
                max_requests=policy.max_requests,
                max_pages=policy.max_pages,
                max_runtime_seconds=policy.max_runtime_seconds,
            ),
            requests=(),
            responses=(),
            dom_snapshots=(),
        )
        report = BrowserDiscoveryReport.create(
            session=session,
            policy=policy,
            result=PlaywrightDiscoveryResult(
                page=None,
                snapshot=snapshot,
                error=None,
            ),
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            store = ResultStore(temp_dir)
            session_path = store.save_session(
                session
            )
            browser_path = store.save_browser_discovery_report(
                report
            )

            self.assertTrue(
                session_path.exists()
            )
            self.assertTrue(
                browser_path.exists()
            )
            self.assertNotEqual(
                session_path,
                browser_path,
            )
            self.assertEqual(
                browser_path.name,
                f"{session.session_id}-browser.json",
            )

            with browser_path.open(
                "r",
                encoding="utf-8",
            ) as file:
                data = json.load(file)

            self.assertEqual(
                data["session_id"],
                session.session_id,
            )
            self.assertEqual(
                data["origin"],
                "https://example.test",
            )
            self.assertEqual(
                data["summary"]["requests_observed"],
                0,
            )


if __name__ == "__main__":
    unittest.main()
