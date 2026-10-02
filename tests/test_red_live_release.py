"""Tests for Red Night Live release metadata and integrity."""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
RED_APP_ROOT = ROOT / "packages" / "red-night"
if str(RED_APP_ROOT) not in sys.path:
    sys.path.insert(0, str(RED_APP_ROOT))

from red_night_app.live_release import (
    EmbeddedPackageArtifact,
    RedEmbeddedPackageManifest,
    RedLiveImageManifest,
    build_live_image_manifest,
    verify_embedded_release_directory,
    verify_live_image_manifest,
)
from red_night_app.sbom import build_red_release_sbom


def digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


class RedLiveReleaseTests(unittest.TestCase):
    def create_release(self, root: Path):
        artifacts_dir = root / "artifacts"
        artifacts_dir.mkdir(parents=True)
        definitions = (
            ("shared.whl", "shared-core-wheel", "nightrecon-shared-core"),
            ("engine.whl", "red-engine-wheel", "nightrecon-red-engine"),
            ("app.whl", "red-app-wheel", "nightrecon-red-night"),
        )
        artifacts = []
        versions = {}
        digests = {}
        for filename, role, distribution in definitions:
            path = artifacts_dir / filename
            path.write_bytes((distribution + "-fixture").encode("utf-8"))
            checksum = digest(path)
            artifacts.append(EmbeddedPackageArtifact(
                filename=filename,
                role=role,
                distribution=distribution,
                version="0.43.0",
                size_bytes=path.stat().st_size,
                sha256=checksum,
            ))
            versions[distribution] = "0.43.0"
            digests[distribution] = checksum

        manifest = RedEmbeddedPackageManifest(
            release_version="0.44.0-dev",
            artifacts=tuple(artifacts),
        )
        sbom = build_red_release_sbom(
            release_version="0.44.0-dev",
            package_versions=versions,
            package_sha256=digests,
        )
        (root / "package-manifest.json").write_text(
            manifest.to_json() + "\n",
            encoding="utf-8",
        )
        (root / "SBOM.json").write_text(
            sbom.to_json() + "\n",
            encoding="utf-8",
        )
        return manifest

    def test_embedded_release_verifies_wheels_and_sbom(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            expected = self.create_release(root)

            actual = verify_embedded_release_directory(root)

            self.assertEqual(actual, expected)

    def test_embedded_release_detects_tampering(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.create_release(root)
            (root / "artifacts" / "app.whl").write_bytes(b"tampered")

            with self.assertRaisesRegex(ValueError, "mismatch"):
                verify_embedded_release_directory(root)

    def test_outer_image_manifest_round_trip_and_verification(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.create_release(root)
            image = root / "RedNight-Live.iso"
            image.write_bytes(b"iso-fixture")

            manifest = build_live_image_manifest(
                release_version="0.44.0-dev",
                source_revision="a" * 40,
                image_path=image,
                package_manifest_path=root / "package-manifest.json",
                sbom_path=root / "SBOM.json",
            )
            decoded = RedLiveImageManifest.from_json(manifest.to_json())

            verify_live_image_manifest(
                decoded,
                image_path=image,
                package_manifest_path=root / "package-manifest.json",
                sbom_path=root / "SBOM.json",
            )
            self.assertEqual(decoded.secure_boot_status, "not-verified")

    def test_outer_manifest_detects_image_tampering(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.create_release(root)
            image = root / "RedNight-Live.iso"
            image.write_bytes(b"iso-fixture")
            manifest = build_live_image_manifest(
                release_version="0.44.0-dev",
                source_revision="b" * 40,
                image_path=image,
                package_manifest_path=root / "package-manifest.json",
                sbom_path=root / "SBOM.json",
            )
            image.write_bytes(b"changed")

            with self.assertRaisesRegex(ValueError, "mismatch"):
                verify_live_image_manifest(
                    manifest,
                    image_path=image,
                    package_manifest_path=root / "package-manifest.json",
                    sbom_path=root / "SBOM.json",
                )


if __name__ == "__main__":
    unittest.main()
