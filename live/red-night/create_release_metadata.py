#!/usr/bin/env python3
"""Create deterministic Red Night Live release metadata."""

from __future__ import annotations

import argparse
from email.parser import Parser
from hashlib import sha256
import json
from pathlib import Path
import shutil
import sys
from zipfile import ZipFile


REPOSITORY = Path(__file__).resolve().parents[2]
RED_APP_ROOT = REPOSITORY / "packages" / "red-night"
if str(RED_APP_ROOT) not in sys.path:
    sys.path.insert(0, str(RED_APP_ROOT))

from red_night_app.live_release import (  # noqa: E402
    EmbeddedPackageArtifact,
    RedEmbeddedPackageManifest,
    RedLiveImageManifest,
    build_live_image_manifest,
    verify_embedded_release_directory,
    verify_live_image_manifest,
)
from red_night_app.sbom import (  # noqa: E402
    build_red_release_sbom,
)


_REQUIRED = (
    ("nightrecon-shared-core", "nightrecon_shared_core-", "shared-core-wheel"),
    ("nightrecon-red-engine", "nightrecon_red_engine-", "red-engine-wheel"),
    ("nightrecon-red-night", "nightrecon_red_night-", "red-app-wheel"),
)


def digest(path: Path) -> str:
    value = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def wheel_metadata(path: Path) -> tuple[str, str]:
    try:
        with ZipFile(path) as archive:
            candidates = sorted(
                name
                for name in archive.namelist()
                if name.endswith(".dist-info/METADATA")
            )
            if len(candidates) != 1:
                raise ValueError(
                    f"wheel must contain exactly one METADATA file: {path.name}"
                )
            text = archive.read(candidates[0]).decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError(f"unable to read wheel metadata: {path.name}") from exc

    metadata = Parser().parsestr(text)
    name = metadata.get("Name")
    version = metadata.get("Version")
    if not name or not version:
        raise ValueError(f"wheel metadata is missing Name/Version: {path.name}")
    return name.strip(), version.strip()


def select_wheels(wheel_dir: Path) -> tuple[tuple[Path, str, str, str], ...]:
    selected: list[tuple[Path, str, str, str]] = []
    for distribution, filename_prefix, role in _REQUIRED:
        matches = tuple(sorted(wheel_dir.glob(f"{filename_prefix}*.whl")))
        if len(matches) != 1:
            raise ValueError(
                f"expected exactly one {distribution} wheel in {wheel_dir}"
            )
        path = matches[0]
        metadata_name, version = wheel_metadata(path)
        if metadata_name.lower().replace("_", "-") != distribution:
            raise ValueError(
                f"wheel distribution identity mismatch for {path.name}: "
                f"{metadata_name}"
            )
        selected.append((path, role, distribution, version))
    return tuple(selected)


def stage_release(
    *,
    wheel_dir: Path,
    output_dir: Path,
    release_version: str,
) -> RedEmbeddedPackageManifest:
    wheel_dir = wheel_dir.resolve()
    output_dir = output_dir.resolve()
    artifacts_dir = output_dir / "artifacts"
    if output_dir.exists():
        shutil.rmtree(output_dir)
    artifacts_dir.mkdir(parents=True)

    artifacts: list[EmbeddedPackageArtifact] = []
    package_versions: dict[str, str] = {}
    package_sha256: dict[str, str] = {}

    selected = select_wheels(wheel_dir)
    stack_versions = {version for _, _, _, version in selected}
    if len(stack_versions) != 1:
        raise ValueError("Red Live package versions must match exactly")

    for source, role, distribution, version in selected:
        destination = artifacts_dir / source.name
        shutil.copy2(source, destination)
        checksum = digest(destination)
        artifacts.append(EmbeddedPackageArtifact(
            filename=destination.name,
            role=role,
            distribution=distribution,
            version=version,
            size_bytes=destination.stat().st_size,
            sha256=checksum,
        ))
        package_versions[distribution] = version
        package_sha256[distribution] = checksum

    manifest = RedEmbeddedPackageManifest(
        release_version=release_version,
        artifacts=tuple(artifacts),
    )
    sbom = build_red_release_sbom(
        release_version=release_version,
        package_versions=package_versions,
        package_sha256=package_sha256,
    )
    (output_dir / "package-manifest.json").write_text(
        manifest.to_json() + "\n",
        encoding="utf-8",
    )
    (output_dir / "SBOM.json").write_text(
        sbom.to_json() + "\n",
        encoding="utf-8",
    )
    verify_embedded_release_directory(output_dir)
    return manifest


def finalize_release(
    *,
    release_dir: Path,
    image_path: Path,
    source_revision: str,
    release_version: str,
    output_manifest: Path,
) -> RedLiveImageManifest:
    release_dir = release_dir.resolve()
    embedded = verify_embedded_release_directory(release_dir)
    if embedded.release_version != release_version:
        raise ValueError("release version differs from staged metadata")

    manifest = build_live_image_manifest(
        release_version=release_version,
        source_revision=source_revision,
        image_path=image_path.resolve(),
        package_manifest_path=release_dir / "package-manifest.json",
        sbom_path=release_dir / "SBOM.json",
    )
    verify_live_image_manifest(
        manifest,
        image_path=image_path.resolve(),
        package_manifest_path=release_dir / "package-manifest.json",
        sbom_path=release_dir / "SBOM.json",
    )
    output_manifest.parent.mkdir(parents=True, exist_ok=True)
    output_manifest.write_text(manifest.to_json() + "\n", encoding="utf-8")
    return manifest


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="create_release_metadata.py")
    commands = result.add_subparsers(dest="command", required=True)

    stage = commands.add_parser("stage")
    stage.add_argument("--wheel-dir", required=True)
    stage.add_argument("--output-dir", required=True)
    stage.add_argument("--release-version", required=True)

    finalize = commands.add_parser("finalize")
    finalize.add_argument("--release-dir", required=True)
    finalize.add_argument("--image", required=True)
    finalize.add_argument("--source-revision", required=True)
    finalize.add_argument("--release-version", required=True)
    finalize.add_argument("--output-manifest", required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "stage":
            stage_release(
                wheel_dir=Path(args.wheel_dir),
                output_dir=Path(args.output_dir),
                release_version=args.release_version,
            )
        else:
            finalize_release(
                release_dir=Path(args.release_dir),
                image_path=Path(args.image),
                source_revision=args.source_revision,
                release_version=args.release_version,
                output_manifest=Path(args.output_manifest),
            )
    except (OSError, ValueError) as exc:
        print(f"red-live release metadata: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
