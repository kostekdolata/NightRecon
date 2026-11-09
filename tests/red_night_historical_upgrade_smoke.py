"""Offline historical-source package upgrade and rollback acceptance.

Uses the immutable v0.43.0 commit, not a synthetic version rewrite.
No network targets or scanners are contacted.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import venv

from red_night_lifecycle_smoke import (
    REPOSITORY, BASELINE_VERSION, build_wheels, install_stack,
    installed_versions, scripts, create_workspace, assert_workspace_preserved,
    assert_stack_compatible,
)

HISTORICAL_SHA = "d99e76b2bdb4ec6a00b74946633e8299a41e7317"
PACKAGES = ("shared-core", "red-engine", "red-night")


def run(*args: str, cwd: Path) -> str:
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=240)
    if result.returncode:
        raise AssertionError(f"command failed: {args[0]} ({result.returncode}): {result.stderr[-1600:]}")
    return result.stdout.strip()


def source_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for package in PACKAGES:
        directory = root / "packages" / package
        if not directory.is_dir():
            raise AssertionError(f"missing historical package: {package}")
        for path in sorted(directory.rglob("*.py")):
            digest.update(path.relative_to(root).as_posix().encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="red-historical-upgrade-") as directory:
        root = Path(directory)
        historical = root / "historical"
        historical.mkdir()
        # CI checks out complete history; no remote fetch is performed by this test.
        actual = run("git", "rev-parse", f"{HISTORICAL_SHA}^{{commit}}", cwd=REPOSITORY)
        assert actual == HISTORICAL_SHA, "historical commit unavailable or mismatched"
        run("git", "archive", "--format=tar", "--output", str(root / "historical.tar"), HISTORICAL_SHA, cwd=REPOSITORY)
        import tarfile
        with tarfile.open(root / "historical.tar") as archive:
            # Reject unsafe paths before extraction.
            for member in archive.getmembers():
                target = (historical / member.name).resolve()
                if not target.is_relative_to(historical.resolve()) or member.issym() or member.islnk():
                    raise AssertionError("unsafe historical archive entry")
            archive.extractall(historical, filter="data")

        assert source_digest(historical) != source_digest(REPOSITORY), "historical and current sources are identical"
        old_wheels, new_wheels = root / "old-wheels", root / "new-wheels"
        old_wheels.mkdir()
        new_wheels.mkdir()
        build_wheels(historical, old_wheels, python=sys.executable)
        build_wheels(REPOSITORY, new_wheels, python=sys.executable)
        environment = root / "venv"
        venv.create(environment, with_pip=True, system_site_packages=True)
        _, python = scripts(environment)
        workspace = root / "workspace"

        install_stack(python, old_wheels, BASELINE_VERSION)
        assert installed_versions(python, root) == (BASELINE_VERSION,) * 3
        # Historical v0.43.0 predates the composition API.
        create_workspace(python, workspace, root)
        assert_workspace_preserved(python, workspace, root)

        # Same published metadata version, different source: force replacement.
        install_stack(python, new_wheels, BASELINE_VERSION, force_reinstall=True)
        assert_stack_compatible(python, BASELINE_VERSION, root)
        assert_workspace_preserved(python, workspace, root)

        install_stack(python, old_wheels, BASELINE_VERSION, force_reinstall=True)
        assert installed_versions(python, root) == (BASELINE_VERSION,) * 3
        assert_workspace_preserved(python, workspace, root)
    print("Historical Red package upgrade and rollback: passed")


if __name__ == "__main__":
    main()
