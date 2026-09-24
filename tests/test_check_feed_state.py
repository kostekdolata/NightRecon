"""Tests for NightRecon signed check-feed replay protection."""

import tempfile
import unittest
from pathlib import Path

from nightrecon.check_feed import (
    CheckFeedPackEntry,
    CheckPackFeed,
)
from nightrecon.check_feed_state import (
    CheckFeedStateStore,
)


class CheckFeedStateStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.store = CheckFeedStateStore(
            self.root
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def feed(
        self,
        *,
        generated_at="2026-09-24T22:30:00Z",
        version="1.0.0",
        sha256="a" * 64,
    ):
        return CheckPackFeed(
            schema_version=1,
            feed_id="nightrecon.official",
            generated_at=generated_at,
            packs=(
                CheckFeedPackEntry(
                    pack_id="nightrecon.web.baseline",
                    version=version,
                    url="https://updates.example.test/web.json",
                    sha256=sha256,
                    signer_key_id="pack-key",
                ),
            ),
        )

    def test_first_verified_feed_generation_is_accepted_and_persisted(self):
        record = self.store.accept(
            self.feed(),
            source_url="https://updates.example.test/feed.json",
        )

        self.assertEqual(
            record.feed_id,
            "nightrecon.official",
        )
        self.assertEqual(
            record.generated_at,
            "2026-09-24T22:30:00Z",
        )
        self.assertEqual(
            self.store.get(
                "nightrecon.official"
            ),
            record,
        )

    def test_older_verified_feed_generation_is_rejected(self):
        self.store.accept(
            self.feed(
                generated_at="2026-09-24T22:30:00Z"
            ),
            source_url="https://updates.example.test/feed.json",
        )

        with self.assertRaisesRegex(
            ValueError,
            "older.*replay",
        ):
            self.store.accept(
                self.feed(
                    generated_at="2026-09-24T22:00:00Z"
                ),
                source_url="https://updates.example.test/feed.json",
            )

    def test_same_generation_with_different_payload_is_rejected(self):
        self.store.accept(
            self.feed(),
            source_url="https://updates.example.test/feed.json",
        )

        with self.assertRaisesRegex(
            ValueError,
            "same generation",
        ):
            self.store.accept(
                self.feed(
                    version="1.1.0",
                    sha256="b" * 64,
                ),
                source_url="https://updates.example.test/feed.json",
            )

    def test_identical_generation_can_be_retried_idempotently(self):
        first = self.store.accept(
            self.feed(),
            source_url="https://updates.example.test/feed.json",
        )
        second = self.store.accept(
            self.feed(),
            source_url="https://updates.example.test/feed.json",
        )

        self.assertEqual(second, first)

    def test_newer_generation_replaces_previous_state(self):
        self.store.accept(
            self.feed(),
            source_url="https://updates.example.test/feed.json",
        )

        newer = self.store.accept(
            self.feed(
                generated_at="2026-09-24T23:00:00Z",
                version="1.1.0",
                sha256="b" * 64,
            ),
            source_url="https://updates.example.test/feed.json",
        )

        self.assertEqual(
            newer.generated_at,
            "2026-09-24T23:00:00Z",
        )

    def test_managed_feed_requires_timezone_aware_generation_timestamp(self):
        with self.assertRaisesRegex(
            ValueError,
            "generated_at",
        ):
            self.store.accept(
                self.feed(
                    generated_at="2026-09-24T22:30:00"
                ),
                source_url="https://updates.example.test/feed.json",
            )


if __name__ == "__main__":
    unittest.main()
