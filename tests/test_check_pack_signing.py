"""Tests for signed NightRecon declarative check packs."""

import base64
import json
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from nightrecon.check_pack_signing import (
    canonicalize_pack_payload,
    load_signed_check_pack,
    parse_trusted_key_specs,
)


class SignedCheckPackTests(unittest.TestCase):
    def setUp(self):
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.public_key_bytes = self.public_key.public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )
        self.payload = {
            "schema_version": 1,
            "pack_id": "nightrecon.test.signed",
            "name": "Signed Test Pack",
            "version": "1.0.0",
            "checks": [],
        }

    def signed_document(self):
        canonical = canonicalize_pack_payload(
            self.payload
        )
        signature = self.private_key.sign(
            canonical
        )

        return {
            "format": "nightrecon-signed-check-pack-v1",
            "key_id": "test-key",
            "payload": self.payload,
            "signature": base64.b64encode(
                signature
            ).decode("ascii"),
        }

    def test_valid_signature_loads_pack(self):
        result = load_signed_check_pack(
            json.dumps(
                self.signed_document()
            ),
            trusted_keys={
                "test-key": self.public_key_bytes,
            },
        )

        self.assertEqual(
            result.pack_id,
            "nightrecon.test.signed",
        )

    def test_unknown_signer_is_rejected(self):
        with self.assertRaisesRegex(
            ValueError,
            "Untrusted check-pack signer",
        ):
            load_signed_check_pack(
                json.dumps(
                    self.signed_document()
                ),
                trusted_keys={},
            )

    def test_tampered_payload_is_rejected(self):
        document = self.signed_document()
        document["payload"]["version"] = "9.9.9"

        with self.assertRaisesRegex(
            ValueError,
            "Invalid check-pack signature",
        ):
            load_signed_check_pack(
                json.dumps(document),
                trusted_keys={
                    "test-key": self.public_key_bytes,
                },
            )

    def test_trusted_key_specs_parse_base64_public_keys(self):
        encoded = base64.b64encode(
            self.public_key_bytes
        ).decode("ascii")

        result = parse_trusted_key_specs(
            (f"test-key={encoded}",)
        )

        self.assertEqual(
            result,
            {
                "test-key": self.public_key_bytes,
            },
        )

    def test_duplicate_trusted_key_id_is_rejected(self):
        encoded = base64.b64encode(
            self.public_key_bytes
        ).decode("ascii")

        with self.assertRaisesRegex(
            ValueError,
            "Duplicate trusted check-pack key",
        ):
            parse_trusted_key_specs(
                (
                    f"test-key={encoded}",
                    f"test-key={encoded}",
                )
            )

    def test_invalid_signature_encoding_is_rejected(self):
        document = self.signed_document()
        document["signature"] = "%%%"

        with self.assertRaisesRegex(
            ValueError,
            "Invalid check-pack signature encoding",
        ):
            load_signed_check_pack(
                json.dumps(document),
                trusted_keys={
                    "test-key": self.public_key_bytes,
                },
            )


if __name__ == "__main__":
    unittest.main()
