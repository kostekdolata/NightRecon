"""Tests for deterministic Red release artifact manifests."""

import sys
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
RED_APP_ROOT = ROOT / "packages" / "red-night"
if str(RED_APP_ROOT) not in sys.path:
    sys.path.insert(0, str(RED_APP_ROOT))

from red_night_app.release_integrity import (
    RedReleaseManifest,
    build_red_release_manifest,
    verify_red_release_manifest,
)


class RedReleaseIntegrityTests(unittest.TestCase):
    def fixture(self, root: Path):
        files = []
        for name, role in (
            ("shared.whl", "shared-core-wheel"),
            ("engine.whl", "red-engine-wheel"),
            ("app.whl", "red-app-wheel"),
        ):
            path = root / name
            path.write_bytes((name + "-fixture").encode("utf-8"))
            files.append((path, role))
        return files

    def test_manifest_round_trip_and_verification(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest = build_red_release_manifest(
                release_root=root,
                release_version="0.44.0-dev",
                deployment_profile="standalone",
                artifacts=self.fixture(root),
            )
            decoded = RedReleaseManifest.from_dict(manifest.to_dict())

            verify_red_release_manifest(decoded, release_root=root)
            self.assertEqual(decoded.to_json(), manifest.to_json())

    def test_tampered_artifact_fails_verification(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest = build_red_release_manifest(
                release_root=root,
                release_version="0.44.0-dev",
                deployment_profile="composed",
                artifacts=self.fixture(root),
            )
            (root / "engine.whl").write_bytes(b"tampered")

            with self.assertRaisesRegex(ValueError, "mismatch"):
                verify_red_release_manifest(manifest, release_root=root)

    def test_live_profile_requires_live_image(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with self.assertRaisesRegex(ValueError, "live-image"):
                build_red_release_manifest(
                    release_root=root,
                    release_version="0.44.0-dev",
                    deployment_profile="live-usb",
                    artifacts=self.fixture(root),
                )

    def test_path_traversal_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "relative"):
            RedReleaseManifest.from_dict({
                "format": "nightrecon-red-release-manifest-v1",
                "release_version": "0.44.0-dev",
                "deployment_profile": "standalone",
                "artifacts": [
                    {
                        "path": "../shared.whl",
                        "role": "shared-core-wheel",
                        "size_bytes": 1,
                        "sha256": "0" * 64,
                    },
                    {
                        "path": "engine.whl",
                        "role": "red-engine-wheel",
                        "size_bytes": 1,
                        "sha256": "0" * 64,
                    },
                    {
                        "path": "app.whl",
                        "role": "red-app-wheel",
                        "size_bytes": 1,
                        "sha256": "0" * 64,
                    },
                ],
            })


if __name__ == "__main__":
    unittest.main()
