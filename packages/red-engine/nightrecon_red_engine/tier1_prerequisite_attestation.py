"""Offline Tier 1 executable prerequisite attestation, not tool execution.

Caller pins absolute executable paths and expected SHA-256 values. No PATH
lookup, subprocess, network call, or implicit authorization occurs.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat

from .tier1_capability_plan import TIER1, SUPPORTED_PLATFORMS


class TrustedPrerequisiteError(ValueError):
    """Invalid attestation request (not an absent tool)."""


def attest_tier1_executables(
    *, platform: str, registrations: dict[str, tuple[str, str]],
    max_file_bytes: int = 100_000_000,
) -> dict:
    """Check explicitly registered regular files against pinned digests.

    Missing, changed, symlinked and oversized files fail closed individually.
    A successful digest only attests bytes, not vendor identity or suitability.
    """
    if (platform not in SUPPORTED_PLATFORMS or type(max_file_bytes) is not int
            or not 0 < max_file_bytes <= 100_000_000
            or not isinstance(registrations, dict)
            or len(registrations) > len(TIER1)):
        raise TrustedPrerequisiteError("Invalid platform, registrations or budget")
    for tool, entry in registrations.items():
        if (tool not in TIER1 or not isinstance(entry, tuple) or len(entry) != 2
                or not all(isinstance(x, str) for x in entry)
                or not re.fullmatch(r"[0-9a-f]{64}", entry[1])
                or not entry[0] or len(entry[0]) > 4096
                or any(ord(ch) < 32 for ch in entry[0])
                or not Path(entry[0]).is_absolute()):
            raise TrustedPrerequisiteError("Invalid pinned tool registration")
    results = {}
    for tool in TIER1:
        entry = registrations.get(tool)
        if entry is None:
            results[tool] = {"attested": False, "reason": "not_registered"}
            continue
        path, expected = entry
        try:
            # Do not follow symlinks, including in parent directories.
            parts = Path(path).parts
            current = Path(parts[0])
            for part in parts[1:]:
                current = current / part
                if stat.S_ISLNK(current.lstat().st_mode):
                    raise OSError("Symlink path component")
            metadata = os.stat(path, follow_symlinks=False)
            if not stat.S_ISREG(metadata.st_mode):
                raise OSError("Not a regular file")
            if metadata.st_size > max_file_bytes:
                raise OSError("File budget exceeded")
            digest = hashlib.sha256()
            with open(path, "rb") as handle:
                while chunk := handle.read(65536):
                    digest.update(chunk)
                    if handle.tell() > max_file_bytes:
                        raise OSError("File budget exceeded")
            if os.stat(path, follow_symlinks=False) != metadata:
                raise OSError("File changed during attestation")
            match = digest.hexdigest() == expected
            results[tool] = {
                "attested": match,
                "reason": "pinned_digest_matched" if match else "digest_mismatch",
            }
        except (OSError, ValueError):
            results[tool] = {"attested": False, "reason": "unavailable_or_unsafe_file"}
    return {
        "schema": "red.tier1_prerequisite_attestation.v1",
        "platform": platform,
        "tools": results,
        "available_tools": {tool: value["attested"] for tool, value in results.items()},
        "execution_allowed": False,
        "integration_verified": False,
        "limitations": (
            "Pinned local bytes only; no vendor signature, runtime dependencies, "
            "authorization, sandbox, executor, or operational integration verified."
        ),
    }
