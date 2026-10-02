"""Release metadata contracts for the Red Night Live deployment."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
from typing import Mapping

from red_night_app.sbom import RedReleaseSbom, RedSbomComponent, SBOM_FORMAT

EMBEDDED_PACKAGE_MANIFEST_FORMAT = "nightrecon-red-live-package-manifest-v1"
LIVE_IMAGE_MANIFEST_FORMAT = "nightrecon-red-live-image-manifest-v1"
_REQUIRED_ROLES = {
    "shared-core-wheel": "nightrecon-shared-core",
    "red-engine-wheel": "nightrecon-red-engine",
    "red-app-wheel": "nightrecon-red-night",
}


def _digest(path: Path) -> str:
    value = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def _required_text(value: str, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{field} must be a nonblank trimmed string")
    return value


@dataclass(frozen=True)
class EmbeddedPackageArtifact:
    filename: str
    role: str
    distribution: str
    version: str
    size_bytes: int
    sha256: str

    def __post_init__(self) -> None:
        _required_text(self.filename, "filename")
        if Path(self.filename).name != self.filename:
            raise ValueError("embedded artifact filename must be a basename")
        expected_distribution = _REQUIRED_ROLES.get(self.role)
        if expected_distribution is None:
            raise ValueError(f"unsupported embedded artifact role: {self.role}")
        if self.distribution != expected_distribution:
            raise ValueError("embedded artifact distribution does not match role")
        _required_text(self.version, "version")
        if not isinstance(self.size_bytes, int) or self.size_bytes < 0:
            raise ValueError("size_bytes must be a non-negative integer")
        if (
            not isinstance(self.sha256, str)
            or len(self.sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.sha256)
        ):
            raise ValueError("sha256 must be lowercase hexadecimal")

    def to_dict(self) -> dict[str, object]:
        return {
            "filename": self.filename,
            "role": self.role,
            "distribution": self.distribution,
            "version": self.version,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "EmbeddedPackageArtifact":
        if not isinstance(payload, Mapping) or set(payload) != {
            "filename", "role", "distribution", "version", "size_bytes", "sha256"
        }:
            raise ValueError("embedded package artifact schema is not supported")
        return cls(**dict(payload))


@dataclass(frozen=True)
class RedEmbeddedPackageManifest:
    release_version: str
    artifacts: tuple[EmbeddedPackageArtifact, ...]
    format: str = EMBEDDED_PACKAGE_MANIFEST_FORMAT

    def __post_init__(self) -> None:
        if self.format != EMBEDDED_PACKAGE_MANIFEST_FORMAT:
            raise ValueError("unsupported embedded package manifest format")
        _required_text(self.release_version, "release_version")
        roles = [item.role for item in self.artifacts]
        if set(roles) != set(_REQUIRED_ROLES) or len(roles) != len(_REQUIRED_ROLES):
            raise ValueError("embedded manifest requires exactly the three Red package roles")
        names = [item.filename for item in self.artifacts]
        if len(names) != len(set(names)):
            raise ValueError("embedded artifact filenames must be unique")

    def to_dict(self) -> dict[str, object]:
        return {
            "format": self.format,
            "release_version": self.release_version,
            "artifacts": [item.to_dict() for item in self.artifacts],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "RedEmbeddedPackageManifest":
        if not isinstance(payload, Mapping) or set(payload) != {
            "format", "release_version", "artifacts"
        }:
            raise ValueError("embedded package manifest schema is not supported")
        artifacts = payload["artifacts"]
        if not isinstance(artifacts, list):
            raise ValueError("embedded package artifacts must be a list")
        return cls(
            format=payload["format"],
            release_version=payload["release_version"],
            artifacts=tuple(EmbeddedPackageArtifact.from_dict(item) for item in artifacts),
        )

    @classmethod
    def from_json(cls, text: str) -> "RedEmbeddedPackageManifest":
        try:
            payload = json.loads(text)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError("embedded package manifest is not valid JSON") from exc
        return cls.from_dict(payload)


@dataclass(frozen=True)
class RedLiveImageManifest:
    release_version: str
    source_revision: str
    base_os: str
    architecture: str
    image_filename: str
    image_size_bytes: int
    image_sha256: str
    package_manifest_sha256: str
    sbom_sha256: str
    secure_boot_status: str = "not-verified"
    format: str = LIVE_IMAGE_MANIFEST_FORMAT

    def __post_init__(self) -> None:
        if self.format != LIVE_IMAGE_MANIFEST_FORMAT:
            raise ValueError("unsupported Red Live image manifest format")
        for value, field in (
            (self.release_version, "release_version"),
            (self.source_revision, "source_revision"),
            (self.base_os, "base_os"),
            (self.architecture, "architecture"),
            (self.image_filename, "image_filename"),
        ):
            _required_text(value, field)
        if Path(self.image_filename).name != self.image_filename:
            raise ValueError("image_filename must be a basename")
        if not isinstance(self.image_size_bytes, int) or self.image_size_bytes <= 0:
            raise ValueError("image_size_bytes must be positive")
        for value, field in (
            (self.image_sha256, "image_sha256"),
            (self.package_manifest_sha256, "package_manifest_sha256"),
            (self.sbom_sha256, "sbom_sha256"),
        ):
            if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
                raise ValueError(f"{field} must be lowercase hexadecimal")
        if self.secure_boot_status not in {"not-verified", "verified"}:
            raise ValueError("secure_boot_status must be not-verified or verified")

    def to_dict(self) -> dict[str, object]:
        return {
            "format": self.format,
            "release_version": self.release_version,
            "source_revision": self.source_revision,
            "base_os": self.base_os,
            "architecture": self.architecture,
            "image_filename": self.image_filename,
            "image_size_bytes": self.image_size_bytes,
            "image_sha256": self.image_sha256,
            "package_manifest_sha256": self.package_manifest_sha256,
            "sbom_sha256": self.sbom_sha256,
            "secure_boot_status": self.secure_boot_status,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


def verify_embedded_release_directory(root: Path) -> RedEmbeddedPackageManifest:
    """Verify immutable in-image wheels and their SBOM against packaged metadata."""

    root = root.resolve()
    artifacts_root = root / "artifacts"
    manifest_path = root / "package-manifest.json"
    sbom_path = root / "SBOM.json"
    if not manifest_path.is_file() or not sbom_path.is_file():
        raise ValueError("embedded release metadata is incomplete")

    manifest = RedEmbeddedPackageManifest.from_json(
        manifest_path.read_text(encoding="utf-8")
    )
    try:
        sbom_payload = json.loads(sbom_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("embedded SBOM is not valid JSON") from exc
    if not isinstance(sbom_payload, dict) or sbom_payload.get("format") != SBOM_FORMAT:
        raise ValueError("embedded SBOM format is not supported")
    components = sbom_payload.get("components")
    if not isinstance(components, list):
        raise ValueError("embedded SBOM components must be a list")
    sbom = RedReleaseSbom(
        format=sbom_payload["format"],
        release_version=sbom_payload["release_version"],
        components=tuple(RedSbomComponent(**item) for item in components),
    )

    component_map = {item.name: item for item in sbom.components}
    for artifact in manifest.artifacts:
        path = artifacts_root / artifact.filename
        if not path.is_file():
            raise ValueError(f"embedded release artifact missing: {artifact.filename}")
        if path.stat().st_size != artifact.size_bytes:
            raise ValueError(f"embedded release artifact size mismatch: {artifact.filename}")
        if _digest(path) != artifact.sha256:
            raise ValueError(f"embedded release artifact digest mismatch: {artifact.filename}")
        component = component_map.get(artifact.distribution)
        if component is None:
            raise ValueError(f"SBOM component missing: {artifact.distribution}")
        if component.version != artifact.version or component.sha256 != artifact.sha256:
            raise ValueError(f"SBOM component mismatch: {artifact.distribution}")

    if manifest.release_version != sbom.release_version:
        raise ValueError("embedded manifest and SBOM release versions differ")
    return manifest


def build_live_image_manifest(
    *,
    release_version: str,
    source_revision: str,
    image_path: Path,
    package_manifest_path: Path,
    sbom_path: Path,
    base_os: str = "debian-13-trixie",
    architecture: str = "amd64",
) -> RedLiveImageManifest:
    return RedLiveImageManifest(
        release_version=release_version,
        source_revision=source_revision,
        base_os=base_os,
        architecture=architecture,
        image_filename=image_path.name,
        image_size_bytes=image_path.stat().st_size,
        image_sha256=_digest(image_path),
        package_manifest_sha256=_digest(package_manifest_path),
        sbom_sha256=_digest(sbom_path),
    )
