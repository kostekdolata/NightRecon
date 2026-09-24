"""Tests for NightRecon signed declarative check feeds."""

import base64
import hashlib
import io
import json
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from nightrecon.check_feed import (
    fetch_check_pack,
    fetch_signed_check_pack_text,
    load_signed_check_feed,
)
from nightrecon.check_pack_signing import (
    canonicalize_pack_payload,
)


class CheckFeedTests(unittest.TestCase):
    def setUp(self):
        self.feed_private_key = Ed25519PrivateKey.generate()
        self.feed_public_key = (
            self.feed_private_key.public_key().public_bytes(
                encoding=Encoding.Raw,
                format=PublicFormat.Raw,
            )
        )
        self.pack_private_key = Ed25519PrivateKey.generate()
        self.pack_public_key = (
            self.pack_private_key.public_key().public_bytes(
                encoding=Encoding.Raw,
                format=PublicFormat.Raw,
            )
        )
        self.pack_payload = {
            "schema_version": 1,
            "pack_id": "nightrecon.web.baseline",
            "name": "Web Baseline",
            "version": "1.0.0",
            "checks": [],
        }
        self.pack_document = self._signed_document(
            format_name="nightrecon-signed-check-pack-v1",
            key_id="pack-key",
            payload=self.pack_payload,
            private_key=self.pack_private_key,
        )
        self.pack_bytes = json.dumps(
            self.pack_document
        ).encode("utf-8")

    def _signed_document(
        self,
        *,
        format_name,
        key_id,
        payload,
        private_key,
    ):
        signature = private_key.sign(
            canonicalize_pack_payload(payload)
        )

        return {
            "format": format_name,
            "key_id": key_id,
            "payload": payload,
            "signature": base64.b64encode(
                signature
            ).decode("ascii"),
        }

    def _feed_document(self):
        payload = {
            "schema_version": 1,
            "feed_id": "nightrecon.official",
            "generated_at": "2026-09-24T22:00:00Z",
            "packs": [
                {
                    "pack_id": "nightrecon.web.baseline",
                    "version": "1.0.0",
                    "url": (
                        "https://updates.example.test/"
                        "nightrecon.web.baseline.json"
                    ),
                    "sha256": hashlib.sha256(
                        self.pack_bytes
                    ).hexdigest(),
                    "signer_key_id": "pack-key",
                }
            ],
        }

        return self._signed_document(
            format_name="nightrecon-signed-check-feed-v1",
            key_id="feed-key",
            payload=payload,
            private_key=self.feed_private_key,
        )

    def test_signed_feed_loads_valid_manifest(self):
        feed = load_signed_check_feed(
            json.dumps(
                self._feed_document()
            ),
            trusted_keys={
                "feed-key": self.feed_public_key,
            },
        )

        self.assertEqual(
            feed.feed_id,
            "nightrecon.official",
        )
        self.assertEqual(len(feed.packs), 1)
        self.assertEqual(
            feed.packs[0].pack_id,
            "nightrecon.web.baseline",
        )

    def test_tampered_feed_is_rejected(self):
        document = self._feed_document()
        document["payload"]["packs"][0]["version"] = "9.9.9"

        with self.assertRaisesRegex(
            ValueError,
            "Invalid check-feed signature",
        ):
            load_signed_check_feed(
                json.dumps(document),
                trusted_keys={
                    "feed-key": self.feed_public_key,
                },
            )

    def test_feed_rejects_non_https_pack_url(self):
        document = self._feed_document()
        document["payload"]["packs"][0]["url"] = (
            "http://updates.example.test/pack.json"
        )
        payload = document["payload"]
        document["signature"] = base64.b64encode(
            self.feed_private_key.sign(
                canonicalize_pack_payload(payload)
            )
        ).decode("ascii")

        with self.assertRaisesRegex(
            ValueError,
            "HTTPS",
        ):
            load_signed_check_feed(
                json.dumps(document),
                trusted_keys={
                    "feed-key": self.feed_public_key,
                },
            )

    def test_fetch_pack_verifies_hash_signer_and_signature(self):
        feed = load_signed_check_feed(
            json.dumps(
                self._feed_document()
            ),
            trusted_keys={
                "feed-key": self.feed_public_key,
            },
        )

        with patch(
            "nightrecon.check_feed.urlopen",
            return_value=io.BytesIO(
                self.pack_bytes
            ),
        ):
            pack = fetch_check_pack(
                feed.packs[0],
                trusted_pack_keys={
                    "pack-key": self.pack_public_key,
                },
                timeout=3.0,
            )

        self.assertEqual(
            pack.pack_id,
            "nightrecon.web.baseline",
        )

    def test_fetch_signed_pack_text_preserves_verified_envelope(self):
        feed = load_signed_check_feed(
            json.dumps(
                self._feed_document()
            ),
            trusted_keys={
                "feed-key": self.feed_public_key,
            },
        )

        with patch(
            "nightrecon.check_feed.urlopen",
            return_value=io.BytesIO(
                self.pack_bytes
            ),
        ):
            text = fetch_signed_check_pack_text(
                feed.packs[0],
                trusted_pack_keys={
                    "pack-key": self.pack_public_key,
                },
                timeout=3.0,
            )

        self.assertEqual(
            json.loads(text),
            self.pack_document,
        )

    def test_fetch_pack_artifact_preserves_signed_document(self):
        feed = load_signed_check_feed(
            json.dumps(
                self._feed_document()
            ),
            trusted_keys={
                "feed-key": self.feed_public_key,
            },
        )

        with patch(
            "nightrecon.check_feed.urlopen",
            return_value=io.BytesIO(
                self.pack_bytes
            ),
        ):
            artifact = fetch_check_pack_artifact(
                feed.packs[0],
                trusted_pack_keys={
                    "pack-key": self.pack_public_key,
                },
            )

        self.assertEqual(
            artifact.pack.pack_id,
            "nightrecon.web.baseline",
        )
        self.assertEqual(
            artifact.signed_text,
            self.pack_bytes.decode("utf-8"),
        )
        self.assertEqual(
            artifact.sha256,
            hashlib.sha256(
                self.pack_bytes
            ).hexdigest(),
        )

    def test_fetch_pack_rejects_hash_mismatch(self):
        feed = load_signed_check_feed(
            json.dumps(
                self._feed_document()
            ),
            trusted_keys={
                "feed-key": self.feed_public_key,
            },
        )

        with patch(
            "nightrecon.check_feed.urlopen",
            return_value=io.BytesIO(
                b"{}"
            ),
        ):
            with self.assertRaisesRegex(
                ValueError,
                "SHA-256",
            ):
                fetch_check_pack(
                    feed.packs[0],
                    trusted_pack_keys={
                        "pack-key": self.pack_public_key,
                    },
                )


if __name__ == "__main__":
    unittest.main()
