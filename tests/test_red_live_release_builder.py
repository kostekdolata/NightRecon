"""Tests for the Red Night Live release metadata builder."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "live" / "red-night" / "create_release_metadata.py"
SPEC = importlib.util.spec_from_file_location("red_live_release_builder", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load Red Live release metadata builder")
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


class RedLiveReleaseBuilderTests(unittest.TestCase):
    def wheel(self, root: Path, distribution: str, version: str) -> Path:
        normalized = distribution.replace("-", "_")
        path = root / f"{normalized}-{version}-py3-none-any.whl"
        dist_info = f"{normalized}-{version}.dist-info"
        with ZipFile(path, "w") as archive:
            archive.writestr(
                f"{dist_info}/METADATA",
                (
                    "Metadata-Version: 2.1\n"
                    f"Name: {distribution}\n"
                    f"Version: {version}\n"
                    "\n"
                ),
            )
        return path

    def populate(self, root: Path, *, engine_version: str = "0.43.0") -> None:
        self.wheel(root, "nightrecon-shared-core", "0.43.0")
        self.wheel(root, "nightrecon-red-engine", engine_version)
        self.wheel(root, "nightrecon-red-night", "0.43.0")

    def test_stage_and_finalize_are_deterministic_and_verifiable(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            wheels = root / "wheels"
            wheels.mkdir()
            self.populate(wheels)
            release = root / "release"

            manifest = builder.stage_release(
                wheel_dir=wheels,
                output_dir=release,
                release_version="0.44.0-dev",
            )

            self.assertEqual(len(manifest.artifacts), 3)
            self.assertTrue((release / "package-manifest.json").is_file())
            self.assertTrue((release / "SBOM.json").is_file())

            image = root / "RedNight-Live.iso"
            image.write_bytes(b"bootable-fixture")
            outer = root / "RedNight-Live.iso.manifest.json"
            image_manifest = builder.finalize_release(
                release_dir=release,
                image_path=image,
                source_revision="c" * 40,
                release_version="0.44.0-dev",
                output_manifest=outer,
            )

            self.assertEqual(image_manifest.source_revision, "c" * 40)
            self.assertEqual(image_manifest.secure_boot_status, "not-verified")
            self.assertTrue(outer.is_file())

    def test_mixed_red_package_versions_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            wheels = root / "wheels"
            wheels.mkdir()
            self.populate(wheels, engine_version="0.44.0")

            with self.assertRaisesRegex(ValueError, "versions must match"):
                builder.stage_release(
                    wheel_dir=wheels,
                    output_dir=root / "release",
                    release_version="0.44.0-dev",
                )


if __name__ == "__main__":
    unittest.main()
