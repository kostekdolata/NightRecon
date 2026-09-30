#!/usr/bin/env python3
"""Validate a built Red Night Live Batch 2 artifact manifest."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: artifact_smoke.py <iso> <manifest.json>")

    iso = Path(sys.argv[1])
    manifest_path = Path(sys.argv[2])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    assert manifest["schema_version"] == 1
    assert manifest["architecture"] == "amd64"
    assert manifest["base_distribution"] == "debian-trixie"
    assert manifest["firmware_boot"] == "uefi"
    assert manifest["secure_boot"] == "disabled-development"
    assert manifest["persistent_workspace"] is False
    assert manifest["host_disk_policy"] == "no-automatic-mount"
    assert manifest["package_install_source"] == "embedded-wheelhouse"
    assert manifest["packages"] == {
        "nightrecon-red-engine": "0.43.0",
        "nightrecon-red-night": "0.43.0",
        "nightrecon-shared-core": "0.43.0",
    }

    digest = hashlib.sha256(iso.read_bytes()).hexdigest()
    assert digest == manifest["sha256"]
    assert manifest["image"] == iso.name
    assert iso.stat().st_size > 0
    print("Red Night Live artifact manifest smoke: passed")


if __name__ == "__main__":
    main()
