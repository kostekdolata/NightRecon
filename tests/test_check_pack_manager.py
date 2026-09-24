"""Tests for NightRecon feed-to-store check-pack management."""

import unittest
from unittest.mock import MagicMock, patch

from nightrecon.check_feed import (
    CheckFeedPackEntry,
    CheckPackFeed,
    VerifiedCheckPackArtifact,
)
from nightrecon.check_pack_manager import (
    CheckPackSyncResult,
    CheckPackUpdatePlan,
    install_pack_from_feed,
    plan_verified_check_feed,
    sync_check_feed,
)
from nightrecon.check_pack_store import (
    InstalledCheckPackRecord,
)
from nightrecon.check_packs import CheckPack


class CheckPackManagerTests(unittest.TestCase):
    def setUp(self):
        self.entry = CheckFeedPackEntry(
            pack_id="nightrecon.web.baseline",
            version="1.0.0",
            url="https://updates.example.test/web.json",
            sha256="a" * 64,
            signer_key_id="pack-key",
        )
        self.feed = CheckPackFeed(
            schema_version=1,
            feed_id="nightrecon.official",
            generated_at="2026-09-24T22:00:00Z",
            packs=(self.entry,),
        )
        self.pack = CheckPack(
            schema_version=1,
            pack_id="nightrecon.web.baseline",
            name="Web Baseline",
            version="1.0.0",
            checks=(),
        )
        self.artifact = VerifiedCheckPackArtifact(
            pack=self.pack,
            signed_text='{"signed":"document"}',
            sha256="a" * 64,
        )

    def test_named_feed_pack_is_verified_and_installed(self):
        store = MagicMock()
        expected = InstalledCheckPackRecord(
            pack_id="nightrecon.web.baseline",
            version="1.0.0",
            signer_key_id="pack-key",
            sha256="a" * 64,
            path="/tmp/pack.json",
        )
        store.install_signed_pack.return_value = expected

        with patch(
            "nightrecon.check_pack_manager.fetch_signed_check_feed",
            return_value=self.feed,
        ) as fetch_feed:
            with patch(
                "nightrecon.check_pack_manager."
                "fetch_check_pack_artifact",
                return_value=self.artifact,
            ) as fetch_pack:
                result = install_pack_from_feed(
                    feed_url=(
                        "https://updates.example.test/feed.json"
                    ),
                    pack_id="nightrecon.web.baseline",
                    feed_trusted_keys={
                        "feed-key": b"f" * 32,
                    },
                    pack_trusted_keys={
                        "pack-key": b"p" * 32,
                    },
                    store=store,
                    timeout=3.0,
                )

        self.assertEqual(result, expected)
        fetch_feed.assert_called_once_with(
            "https://updates.example.test/feed.json",
            trusted_keys={
                "feed-key": b"f" * 32,
            },
            timeout=3.0,
        )
        fetch_pack.assert_called_once_with(
            self.entry,
            trusted_pack_keys={
                "pack-key": b"p" * 32,
            },
            timeout=3.0,
        )
        store.install_signed_pack.assert_called_once_with(
            self.artifact.signed_text,
            trusted_keys={
                "pack-key": b"p" * 32,
            },
        )

    def test_sync_skips_unchanged_and_updates_changed_pack(self):
        second_entry = CheckFeedPackEntry(
            pack_id="nightrecon.tls.baseline",
            version="2.0.0",
            url="https://updates.example.test/tls.json",
            sha256="b" * 64,
            signer_key_id="pack-key",
        )
        feed = CheckPackFeed(
            schema_version=1,
            feed_id="nightrecon.official",
            generated_at="2026-09-24T22:30:00Z",
            packs=(self.entry, second_entry),
        )
        second_pack = CheckPack(
            schema_version=1,
            pack_id="nightrecon.tls.baseline",
            name="TLS Baseline",
            version="2.0.0",
            checks=(),
        )
        second_artifact = VerifiedCheckPackArtifact(
            pack=second_pack,
            signed_text='{"signed":"tls"}',
            sha256="b" * 64,
        )
        store = MagicMock()
        store.active_version.side_effect = lambda pack_id: {
            "nightrecon.web.baseline": "1.0.0",
            "nightrecon.tls.baseline": "1.5.0",
        }[pack_id]
        store.list_versions.return_value = (
            InstalledCheckPackRecord(
                pack_id="nightrecon.web.baseline",
                version="1.0.0",
                signer_key_id="pack-key",
                sha256="a" * 64,
                path="/tmp/web.json",
            ),
        )
        store.install_signed_pack.return_value = (
            InstalledCheckPackRecord(
                pack_id="nightrecon.tls.baseline",
                version="2.0.0",
                signer_key_id="pack-key",
                sha256="b" * 64,
                path="/tmp/tls.json",
            )
        )

        with patch(
            "nightrecon.check_pack_manager.fetch_signed_check_feed",
            return_value=feed,
        ):
            with patch(
                "nightrecon.check_pack_manager."
                "fetch_check_pack_artifact",
                return_value=second_artifact,
            ) as fetch_pack:
                results = sync_check_feed(
                    feed_url=(
                        "https://updates.example.test/feed.json"
                    ),
                    feed_trusted_keys={
                        "feed-key": b"f" * 32,
                    },
                    pack_trusted_keys={
                        "pack-key": b"p" * 32,
                    },
                    store=store,
                    timeout=3.0,
                )

        self.assertEqual(
            results,
            (
                CheckPackSyncResult(
                    pack_id="nightrecon.web.baseline",
                    advertised_version="1.0.0",
                    previous_version="1.0.0",
                    active_version="1.0.0",
                    status="unchanged",
                ),
                CheckPackSyncResult(
                    pack_id="nightrecon.tls.baseline",
                    advertised_version="2.0.0",
                    previous_version="1.5.0",
                    active_version="2.0.0",
                    status="updated",
                ),
            ),
        )
        fetch_pack.assert_called_once_with(
            second_entry,
            trusted_pack_keys={
                "pack-key": b"p" * 32,
            },
            timeout=3.0,
        )

    def test_sync_isolates_pack_failure_and_continues(self):
        second_entry = CheckFeedPackEntry(
            pack_id="nightrecon.tls.baseline",
            version="2.0.0",
            url="https://updates.example.test/tls.json",
            sha256="b" * 64,
            signer_key_id="pack-key",
        )
        feed = CheckPackFeed(
            schema_version=1,
            feed_id="nightrecon.official",
            generated_at="2026-09-24T22:30:00Z",
            packs=(self.entry, second_entry),
        )
        second_pack = CheckPack(
            schema_version=1,
            pack_id="nightrecon.tls.baseline",
            name="TLS Baseline",
            version="2.0.0",
            checks=(),
        )
        second_artifact = VerifiedCheckPackArtifact(
            pack=second_pack,
            signed_text='{"signed":"tls"}',
            sha256="b" * 64,
        )
        store = MagicMock()
        store.active_version.return_value = None
        store.install_signed_pack.return_value = (
            InstalledCheckPackRecord(
                pack_id="nightrecon.tls.baseline",
                version="2.0.0",
                signer_key_id="pack-key",
                sha256="b" * 64,
                path="/tmp/tls.json",
            )
        )

        with patch(
            "nightrecon.check_pack_manager.fetch_signed_check_feed",
            return_value=feed,
        ):
            with patch(
                "nightrecon.check_pack_manager."
                "fetch_check_pack_artifact",
                side_effect=(
                    ValueError("bad pack"),
                    second_artifact,
                ),
            ):
                results = sync_check_feed(
                    feed_url=(
                        "https://updates.example.test/feed.json"
                    ),
                    feed_trusted_keys={
                        "feed-key": b"f" * 32,
                    },
                    pack_trusted_keys={
                        "pack-key": b"p" * 32,
                    },
                    store=store,
                )

        self.assertEqual(results[0].status, "failed")
        self.assertIn("bad pack", results[0].error)
        self.assertEqual(results[1].status, "installed")
        self.assertEqual(results[1].active_version, "2.0.0")

    def test_sync_rejects_same_version_with_different_feed_hash(self):
        store = MagicMock()
        store.active_version.return_value = "1.0.0"
        store.list_versions.return_value = (
            InstalledCheckPackRecord(
                pack_id="nightrecon.web.baseline",
                version="1.0.0",
                signer_key_id="pack-key",
                sha256="b" * 64,
                path="/tmp/web.json",
            ),
        )

        with patch(
            "nightrecon.check_pack_manager.fetch_signed_check_feed",
            return_value=self.feed,
        ):
            with patch(
                "nightrecon.check_pack_manager."
                "fetch_check_pack_artifact"
            ) as fetch_pack:
                results = sync_check_feed(
                    feed_url=(
                        "https://updates.example.test/feed.json"
                    ),
                    feed_trusted_keys={
                        "feed-key": b"f" * 32,
                    },
                    pack_trusted_keys={
                        "pack-key": b"p" * 32,
                    },
                    store=store,
                )

        self.assertEqual(results[0].status, "failed")
        self.assertIn("immutable", results[0].error)
        fetch_pack.assert_not_called()

    def test_update_plan_reports_install_update_activation_and_unchanged(self):
        feed = CheckPackFeed(
            schema_version=1,
            feed_id="nightrecon.official",
            generated_at="2026-09-24T23:00:00Z",
            packs=(
                CheckFeedPackEntry(
                    pack_id="nightrecon.new",
                    version="1.0.0",
                    url="https://updates.example.test/new.json",
                    sha256="1" * 64,
                    signer_key_id="pack-key",
                ),
                CheckFeedPackEntry(
                    pack_id="nightrecon.update",
                    version="2.0.0",
                    url="https://updates.example.test/update.json",
                    sha256="2" * 64,
                    signer_key_id="pack-key",
                ),
                CheckFeedPackEntry(
                    pack_id="nightrecon.cached",
                    version="2.0.0",
                    url="https://updates.example.test/cached.json",
                    sha256="3" * 64,
                    signer_key_id="pack-key",
                ),
                CheckFeedPackEntry(
                    pack_id="nightrecon.same",
                    version="1.0.0",
                    url="https://updates.example.test/same.json",
                    sha256="4" * 64,
                    signer_key_id="pack-key",
                ),
            ),
        )
        store = MagicMock()

        def active_version(pack_id):
            return {
                "nightrecon.new": None,
                "nightrecon.update": "1.0.0",
                "nightrecon.cached": "1.0.0",
                "nightrecon.same": "1.0.0",
            }[pack_id]

        def list_versions(pack_id):
            records = {
                "nightrecon.new": (),
                "nightrecon.update": (),
                "nightrecon.cached": (
                    InstalledCheckPackRecord(
                        pack_id="nightrecon.cached",
                        version="2.0.0",
                        signer_key_id="pack-key",
                        sha256="3" * 64,
                        path="/tmp/cached.json",
                    ),
                ),
                "nightrecon.same": (
                    InstalledCheckPackRecord(
                        pack_id="nightrecon.same",
                        version="1.0.0",
                        signer_key_id="pack-key",
                        sha256="4" * 64,
                        path="/tmp/same.json",
                    ),
                ),
            }
            return records[pack_id]

        store.active_version.side_effect = active_version
        store.list_versions.side_effect = list_versions

        result = plan_verified_check_feed(
            feed=feed,
            store=store,
        )

        self.assertEqual(
            result,
            (
                CheckPackUpdatePlan(
                    pack_id="nightrecon.new",
                    advertised_version="1.0.0",
                    active_version=None,
                    status="install-available",
                    download_required=True,
                ),
                CheckPackUpdatePlan(
                    pack_id="nightrecon.update",
                    advertised_version="2.0.0",
                    active_version="1.0.0",
                    status="change-available",
                    download_required=True,
                ),
                CheckPackUpdatePlan(
                    pack_id="nightrecon.cached",
                    advertised_version="2.0.0",
                    active_version="1.0.0",
                    status="activation-available",
                    download_required=False,
                ),
                CheckPackUpdatePlan(
                    pack_id="nightrecon.same",
                    advertised_version="1.0.0",
                    active_version="1.0.0",
                    status="unchanged",
                    download_required=False,
                ),
            ),
        )

    def test_update_plan_detects_immutable_version_conflict(self):
        store = MagicMock()
        store.active_version.return_value = "1.0.0"
        store.list_versions.return_value = (
            InstalledCheckPackRecord(
                pack_id="nightrecon.web.baseline",
                version="1.0.0",
                signer_key_id="pack-key",
                sha256="b" * 64,
                path="/tmp/web.json",
            ),
        )

        result = plan_verified_check_feed(
            feed=self.feed,
            store=store,
        )

        self.assertEqual(
            result,
            (
                CheckPackUpdatePlan(
                    pack_id="nightrecon.web.baseline",
                    advertised_version="1.0.0",
                    active_version="1.0.0",
                    status="conflict",
                    download_required=False,
                    error=(
                        "Feed attempts to mutate an immutable "
                        "installed check-pack version."
                    ),
                ),
            ),
        )

    def test_missing_pack_id_fails_before_download(self):
        store = MagicMock()

        with patch(
            "nightrecon.check_pack_manager.fetch_signed_check_feed",
            return_value=self.feed,
        ):
            with patch(
                "nightrecon.check_pack_manager."
                "fetch_check_pack_artifact"
            ) as fetch_pack:
                with self.assertRaisesRegex(
                    ValueError,
                    "not advertised",
                ):
                    install_pack_from_feed(
                        feed_url=(
                            "https://updates.example.test/feed.json"
                        ),
                        pack_id="nightrecon.missing",
                        feed_trusted_keys={
                            "feed-key": b"f" * 32,
                        },
                        pack_trusted_keys={
                            "pack-key": b"p" * 32,
                        },
                        store=store,
                    )

        fetch_pack.assert_not_called()
        store.install_signed_pack.assert_not_called()


if __name__ == "__main__":
    unittest.main()
