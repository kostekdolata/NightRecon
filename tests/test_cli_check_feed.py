"""CLI tests for signed NightRecon check feeds."""

import base64
import contextlib
import io
import sys
import unittest
from unittest.mock import patch

from nightrecon.check_feed import (
    CheckFeedPackEntry,
    CheckPackFeed,
)
from nightrecon.cli import main


class CliCheckFeedTests(unittest.TestCase):
    def setUp(self):
        self.key_bytes = b"f" * 32
        self.key_spec = (
            "feed-key="
            + base64.b64encode(
                self.key_bytes
            ).decode("ascii")
        )

    def test_checks_feed_displays_verified_feed_entries(self):
        feed = CheckPackFeed(
            schema_version=1,
            feed_id="nightrecon.official",
            generated_at="2026-09-24T22:00:00Z",
            packs=(
                CheckFeedPackEntry(
                    pack_id="nightrecon.web.baseline",
                    version="1.0.0",
                    url=(
                        "https://updates.example.test/"
                        "nightrecon.web.baseline.json"
                    ),
                    sha256="a" * 64,
                    signer_key_id="pack-key",
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
                "checks",
                "feed",
                "--url",
                "https://updates.example.test/feed.json",
                "--feed-key",
                self.key_spec,
            ],
        ):
            with patch(
                "nightrecon.cli.fetch_signed_check_feed",
                return_value=feed,
            ) as fetch:
                with contextlib.redirect_stdout(stdout):
                    with contextlib.redirect_stderr(stderr):
                        main()

        self.assertEqual(stderr.getvalue(), "")
        self.assertIn(
            "Feed: nightrecon.official",
            stdout.getvalue(),
        )
        self.assertIn(
            "nightrecon.web.baseline version=1.0.0 signer=pack-key",
            stdout.getvalue(),
        )
        fetch.assert_called_once_with(
            "https://updates.example.test/feed.json",
            trusted_keys={
                "feed-key": self.key_bytes,
            },
        )

    def test_checks_feed_verification_failure_is_fatal(self):
        stderr = io.StringIO()

        with patch.object(
            sys,
            "argv",
            [
                "nightrecon",
                "checks",
                "feed",
                "--url",
                "https://updates.example.test/feed.json",
                "--feed-key",
                self.key_spec,
            ],
        ):
            with patch(
                "nightrecon.cli.fetch_signed_check_feed",
                side_effect=ValueError(
                    "Invalid check-feed signature."
                ),
            ):
                with contextlib.redirect_stderr(stderr):
                    with self.assertRaises(SystemExit) as exc:
                        main()

        self.assertEqual(exc.exception.code, 2)
        self.assertIn(
            "Invalid check-feed signature.",
            stderr.getvalue(),
        )


if __name__ == "__main__":
    unittest.main()
