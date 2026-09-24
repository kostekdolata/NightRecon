"""Tests for NightRecon feed-to-store check-pack management."""

import unittest
from unittest.mock import MagicMock, patch

from nightrecon.check_feed import (
    CheckFeedPackEntry,
    CheckPackFeed,
    VerifiedCheckPackArtifact,
)
from nightrecon.check_pack_manager import (
    install_pack_from_feed,
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
