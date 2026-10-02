"""Deterministic, secret-free Red Night release SBOM contract."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Mapping

SBOM_FORMAT = "nightrecon-red-sbom-v1"
_REQUIRED_COMPONENTS = (
    "nightrecon-shared-core",
    "nightrecon-red-engine",
    "nightrecon-red-night",
)


@dataclass(frozen=True)
class RedSbomComponent:
    name: str
    version: str
    sha256: str

    def __post_init__(self) -> None:
        if not self.name or self.name != self.name.strip():
            raise ValueError("SBOM component name must be nonblank")
        if not self.version or self.version != self.version.strip():
            raise ValueError("SBOM component version must be nonblank")
        if (
            len(self.sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.sha256)
        ):
            raise ValueError("SBOM component sha256 must be lowercase hexadecimal")

    def to_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "version": self.version,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class RedReleaseSbom:
    release_version: str
    components: tuple[RedSbomComponent, ...]
    format: str = SBOM_FORMAT

    def __post_init__(self) -> None:
        if self.format != SBOM_FORMAT:
            raise ValueError("unsupported Red SBOM format")
        names = [item.name for item in self.components]
        if len(names) != len(set(names)):
            raise ValueError("SBOM component names must be unique")
        for required in _REQUIRED_COMPONENTS:
            if names.count(required) != 1:
                raise ValueError(f"SBOM requires exactly one {required} component")

    def to_dict(self) -> dict[str, object]:
        return {
            "format": self.format,
            "release_version": self.release_version,
            "components": [item.to_dict() for item in self.components],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


def build_red_release_sbom(
    *,
    release_version: str,
    package_versions: Mapping[str, str],
    package_sha256: Mapping[str, str],
) -> RedReleaseSbom:
    if set(package_versions) != set(package_sha256):
        raise ValueError("SBOM version and digest component sets must match")
    return RedReleaseSbom(
        release_version=release_version,
        components=tuple(
            RedSbomComponent(
                name=name,
                version=package_versions[name],
                sha256=package_sha256[name],
            )
            for name in sorted(package_versions)
        ),
    )
