"""Tests for signed offline Red release verification."""

import base64
import json
import sys
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[1]
RED_APP_ROOT = ROOT / "packages" / "red-night"
if str(RED_APP_ROOT) not in sys.path:
    sys.path.insert(0, str(RED_APP_ROOT))

from red_night_app.offline_update import (
    SIGNED_UPDATE_FORMAT,
    canonicalize_update_payload,
    verify_signed_offline_update,
)
from red_night_app.release_integrity import build_red_release_manifest


class RedOfflineUpdateTests(unittest.TestCase):
    def setUp(self):
        self.private = Ed25519PrivateKey.generate()
        self.public = self.private.public_key().public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )

    def fixture_manifest(self, root: Path):
        artifacts = []
        for name, role in (
            ("shared.whl", "shared-core-wheel"),
            ("engine.whl", "red-engine-wheel"),
            ("app.whl", "red-app-wheel"),
        ):
            path = root / name
            path.write_bytes(name.encode("utf-8"))
            artifacts.append((path, role))
        return build_red_release_manifest(
            release_root=root,
            release_version="0.44.0-dev",
            deployment_profile="standalone",
            artifacts=artifacts,
        )

    def signed_document(self, payload):
        signature = self.private.sign(canonicalize_update_payload(payload))
        return json.dumps({
            "format": SIGNED_UPDATE_FORMAT,
            "key_id": "release-test",
            "payload": payload,
            "signature": base64.b64encode(signature).decode("ascii"),
        })

    def test_valid_signed_bundle_verifies_artifacts(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest = self.fixture_manifest(root)

            result = verify_signed_offline_update(
                self.signed_document(manifest.to_dict()),
                trusted_keys={"release-test": self.public},
                release_root=root,
            )

            self.assertEqual(result.release_version, "0.44.0-dev")

    def test_untrusted_signer_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest = self.fixture_manifest(root)

            with self.assertRaisesRegex(ValueError, "untrusted"):
                verify_signed_offline_update(
                    self.signed_document(manifest.to_dict()),
                    trusted_keys={},
                    release_root=root,
                )

    def test_signed_manifest_with_tampered_artifact_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest = self.fixture_manifest(root)
            document = self.signed_document(manifest.to_dict())
            (root / "app.whl").write_bytes(b"changed")

            with self.assertRaisesRegex(ValueError, "mismatch"):
                verify_signed_offline_update(
                    document,
                    trusted_keys={"release-test": self.public},
                    release_root=root,
                )

    def test_tampered_signed_payload_fails_signature(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest = self.fixture_manifest(root)
            document = json.loads(self.signed_document(manifest.to_dict()))
            document["payload"]["release_version"] = "9.9.9"

            with self.assertRaisesRegex(ValueError, "invalid offline update signature"):
                verify_signed_offline_update(
                    json.dumps(document),
                    trusted_keys={"release-test": self.public},
                    release_root=root,
                )


if __name__ == "__main__":
    unittest.main()
