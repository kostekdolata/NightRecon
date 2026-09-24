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
from nightrecon.check_pack_manager import CheckPackSyncResult
from nightrecon.check_pack_store import InstalledCheckPackRecord
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
        self.pack_key_bytes = b"p" * 32
        self.pack_key_spec = (
            "pack-key="
            + base64.b64encode(
                self.pack_key_bytes
            ).decode("ascii")
        )

    def _feed_entry(self):
        return CheckFeedPackEntry(
            pack_id="nightrecon.web.baseline",
            version="1.1.0",
            url="https://updates.example.test/web.json",
            sha256="b" * 64,
            signer_key_id="pack-key",
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

    def test_checks_feed_can_install_named_pack(self):
        feed = CheckPackFeed(
            schema_version=1,
            feed_id="nightrecon.official",
            generated_at="2026-09-24T22:00:00Z",
            packs=(
                CheckFeedPackEntry(
                    pack_id="nightrecon.web.baseline",
                    version="1.0.0",
                    url="https://updates.example.test/web.json",
                    sha256="a" * 64,
                    signer_key_id="pack-key",
                ),
            ),
        )
        installed = InstalledCheckPackRecord(
            pack_id="nightrecon.web.baseline",
            version="1.0.0",
            signer_key_id="pack-key",
            sha256="a" * 64,
            path="pack-store/packs/nightrecon.web.baseline/1.0.0.signed.json",
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
                "--install-pack",
                "nightrecon.web.baseline",
                "--pack-key",
                self.pack_key_spec,
                "--store-dir",
                "pack-store",
            ],
        ):
            with patch(
                "nightrecon.cli.fetch_signed_check_feed",
                return_value=feed,
            ):
                with patch(
                    "nightrecon.cli.CheckPackStore"
                ) as store_class:
                    store = store_class.return_value

                    with patch(
                        "nightrecon.cli.install_pack_from_verified_feed",
                        return_value=installed,
                    ) as install:
                        with contextlib.redirect_stdout(stdout):
                            with contextlib.redirect_stderr(stderr):
                                main()

        self.assertEqual(stderr.getvalue(), "")
        self.assertIn(
            "Installed: nightrecon.web.baseline version=1.0.0",
            stdout.getvalue(),
        )
        store_class.assert_called_once_with(
            "pack-store"
        )
        install.assert_called_once_with(
            feed=feed,
            pack_id="nightrecon.web.baseline",
            pack_trusted_keys={
                "pack-key": self.pack_key_bytes,
            },
            store=store,
        )

    def test_checks_feed_can_sync_all_advertised_packs(self):
        feed = CheckPackFeed(
            schema_version=1,
            feed_id="nightrecon.official",
            generated_at="2026-09-24T22:30:00Z",
            packs=(self._feed_entry(),),
        )
        results = (
            CheckPackSyncResult(
                pack_id="nightrecon.web.baseline",
                advertised_version="1.1.0",
                previous_version="1.0.0",
                active_version="1.1.0",
                status="updated",
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
                "--sync",
                "--pack-key",
                self.pack_key_spec,
                "--store-dir",
                "pack-store",
            ],
        ):
            with patch(
                "nightrecon.cli.fetch_signed_check_feed",
                return_value=feed,
            ):
                with patch(
                    "nightrecon.cli.CheckPackStore"
                ) as store_class:
                    store = store_class.return_value

                    with patch(
                        "nightrecon.cli.sync_verified_check_feed",
                        return_value=results,
                    ) as sync:
                        with contextlib.redirect_stdout(stdout):
                            with contextlib.redirect_stderr(stderr):
                                main()

        self.assertEqual(stderr.getvalue(), "")
        self.assertIn(
            "SYNC nightrecon.web.baseline status=updated "
            "advertised=1.1.0 previous=1.0.0 active=1.1.0",
            stdout.getvalue(),
        )
        sync.assert_called_once_with(
            feed=feed,
            pack_trusted_keys={
                "pack-key": self.pack_key_bytes,
            },
            store=store,
        )

    def test_checks_feed_lists_installed_packs_offline(self):
        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch.object(
            sys,
            "argv",
            [
                "nightrecon",
                "checks",
                "feed",
                "--list-installed",
                "--store-dir",
                "pack-store",
            ],
        ):
            with patch(
                "nightrecon.cli.CheckPackStore"
            ) as store_class:
                store = store_class.return_value
                store.list_pack_ids.return_value = (
                    "nightrecon.web.baseline",
                )
                store.active_version.return_value = "1.1.0"
                store.list_versions.return_value = (
                    InstalledCheckPackRecord(
                        pack_id="nightrecon.web.baseline",
                        version="1.0.0",
                        signer_key_id="pack-key",
                        sha256="a" * 64,
                        path="/tmp/1.0.0.json",
                    ),
                    InstalledCheckPackRecord(
                        pack_id="nightrecon.web.baseline",
                        version="1.1.0",
                        signer_key_id="pack-key",
                        sha256="b" * 64,
                        path="/tmp/1.1.0.json",
                    ),
                )

                with contextlib.redirect_stdout(stdout):
                    with contextlib.redirect_stderr(stderr):
                        main()

        self.assertEqual(stderr.getvalue(), "")
        self.assertIn(
            "Installed Pack: nightrecon.web.baseline active=1.1.0",
            stdout.getvalue(),
        )
        self.assertIn(
            "version=1.0.0",
            stdout.getvalue(),
        )
        self.assertIn(
            "version=1.1.0",
            stdout.getvalue(),
        )

    def test_checks_feed_rolls_back_pack_offline(self):
        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch.object(
            sys,
            "argv",
            [
                "nightrecon",
                "checks",
                "feed",
                "--rollback-pack",
                "nightrecon.web.baseline",
                "--pack-key",
                self.pack_key_spec,
                "--store-dir",
                "pack-store",
            ],
        ):
            with patch(
                "nightrecon.cli.CheckPackStore"
            ) as store_class:
                store = store_class.return_value
                store.rollback_verified.return_value = "1.0.0"

                with contextlib.redirect_stdout(stdout):
                    with contextlib.redirect_stderr(stderr):
                        main()

        self.assertEqual(stderr.getvalue(), "")
        self.assertIn(
            "Rolled back: nightrecon.web.baseline active=1.0.0",
            stdout.getvalue(),
        )
        store.rollback_verified.assert_called_once_with(
            "nightrecon.web.baseline",
            trusted_keys={
                "pack-key": self.pack_key_bytes,
            },
        )

    def test_checks_feed_install_requires_pack_key(self):
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
                "--install-pack",
                "nightrecon.web.baseline",
            ],
        ):
            with contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as exc:
                    main()

        self.assertEqual(exc.exception.code, 2)
        self.assertIn(
            "--install-pack requires --pack-key",
            stderr.getvalue(),
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
