"""Tests for NightRecon installed signed check-pack storage."""

import base64
import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from nightrecon.check_pack_signing import (
    canonicalize_pack_payload,
)
from nightrecon.check_pack_store import CheckPackStore


class CheckPackStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key().public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )
        self.trusted = {
            "official": self.public_key,
        }

    def tearDown(self):
        self.temp_dir.cleanup()

    def signed_pack(
        self,
        *,
        version,
        name="Web Baseline",
        pack_id="nightrecon.web.baseline",
    ):
        payload = {
            "schema_version": 1,
            "pack_id": pack_id,
            "name": name,
            "version": version,
            "checks": [],
        }
        signature = self.private_key.sign(
            canonicalize_pack_payload(payload)
        )
        return json.dumps(
            {
                "format": "nightrecon-signed-check-pack-v1",
                "key_id": "official",
                "payload": payload,
                "signature": base64.b64encode(
                    signature
                ).decode("ascii"),
            }
        )

    def test_install_sets_active_version_and_retains_verified_metadata(self):
        store = CheckPackStore(self.root)

        record = store.install_signed_pack(
            self.signed_pack(version="1.0.0"),
            trusted_keys=self.trusted,
        )

        self.assertEqual(record.pack_id, "nightrecon.web.baseline")
        self.assertEqual(record.version, "1.0.0")
        self.assertEqual(record.signer_key_id, "official")
        self.assertEqual(
            store.active_version(
                "nightrecon.web.baseline"
            ),
            "1.0.0",
        )
        self.assertEqual(
            tuple(
                item.version
                for item in store.list_versions(
                    "nightrecon.web.baseline"
                )
            ),
            ("1.0.0",),
        )

    def test_installing_new_version_retains_old_and_rollback_restores_it(self):
        store = CheckPackStore(self.root)

        store.install_signed_pack(
            self.signed_pack(version="1.0.0"),
            trusted_keys=self.trusted,
        )
        store.install_signed_pack(
            self.signed_pack(version="1.1.0"),
            trusted_keys=self.trusted,
        )

        self.assertEqual(
            store.active_version(
                "nightrecon.web.baseline"
            ),
            "1.1.0",
        )
        self.assertEqual(
            tuple(
                item.version
                for item in store.list_versions(
                    "nightrecon.web.baseline"
                )
            ),
            ("1.0.0", "1.1.0"),
        )

        restored = store.rollback(
            "nightrecon.web.baseline"
        )

        self.assertEqual(restored, "1.0.0")
        self.assertEqual(
            store.active_version(
                "nightrecon.web.baseline"
            ),
            "1.0.0",
        )

    def test_cached_pack_is_reverified_when_loaded(self):
        store = CheckPackStore(self.root)
        record = store.install_signed_pack(
            self.signed_pack(version="1.0.0"),
            trusted_keys=self.trusted,
        )

        Path(record.path).write_text(
            "{}",
            encoding="utf-8",
        )

        with self.assertRaises(ValueError):
            store.load_active(
                "nightrecon.web.baseline",
                trusted_keys=self.trusted,
            )

    def test_existing_version_cannot_be_replaced_with_different_bytes(self):
        store = CheckPackStore(self.root)

        store.install_signed_pack(
            self.signed_pack(
                version="1.0.0",
                name="Original",
            ),
            trusted_keys=self.trusted,
        )

        with self.assertRaisesRegex(
            ValueError,
            "immutable",
        ):
            store.install_signed_pack(
                self.signed_pack(
                    version="1.0.0",
                    name="Changed",
                ),
                trusted_keys=self.trusted,
            )

    def test_unsafe_pack_id_is_rejected_for_storage(self):
        store = CheckPackStore(self.root)

        with self.assertRaisesRegex(
            ValueError,
            "Unsafe check-pack ID",
        ):
            store.install_signed_pack(
                self.signed_pack(
                    version="1.0.0",
                    pack_id="../escape",
                ),
                trusted_keys=self.trusted,
            )

    def test_rollback_without_previous_active_version_fails(self):
        store = CheckPackStore(self.root)
        store.install_signed_pack(
            self.signed_pack(version="1.0.0"),
            trusted_keys=self.trusted,
        )

        with self.assertRaisesRegex(
            ValueError,
            "No previous active version",
        ):
            store.rollback(
                "nightrecon.web.baseline"
            )


if __name__ == "__main__":
    unittest.main()
