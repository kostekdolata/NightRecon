"""Disposable root-only Red Night LUKS2 executor integration fixture.

CI creates a regular-file encrypted container and exposes it through a temporary
/dev/disk/by-id/...-part1 symlink so the real Red persistence executor exercises
its production selector contract without touching any physical host disk.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
RED_APP_ROOT = ROOT / "packages" / "red-night"
if str(RED_APP_ROOT) not in sys.path:
    sys.path.insert(0, str(RED_APP_ROOT))

from red_night_app.persistence import (  # noqa: E402
    RedPersistenceConfig,
    RedPersistenceState,
    WORKSPACE_MAPPER_NAME,
    WORKSPACE_MOUNT_POINT,
)
from red_night_app.persistence_executor import (  # noqa: E402
    PersistenceExecutionError,
    mount_workspace,
    probe_workspace_state,
    provision_workspace,
    safe_close_workspace,
    unlock_workspace,
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_root() -> None:
    if os.geteuid() != 0:
        raise SystemExit("red_live_luks_executor_runtime.py must run as root")


def require_tools() -> None:
    for name in ("cryptsetup", "mkfs.ext4", "mount", "umount"):
        if shutil.which(name) is None:
            raise SystemExit(f"required command not found: {name}")


def main() -> int:
    require_root()
    require_tools()

    mountpoint = Path(WORKSPACE_MOUNT_POINT)
    mapper = Path("/dev/mapper") / WORKSPACE_MAPPER_NAME
    by_id_dir = Path("/dev/disk/by-id")

    with tempfile.TemporaryDirectory(prefix="red-night-luks-fixture-") as raw:
        temp = Path(raw)
        image = temp / "workspace.img"
        selector = by_id_dir / f"red-night-ci-{os.getpid()}-part1"
        state_file = mountpoint / "engagements" / "ci-state.txt"
        secret = os.urandom(48).hex().encode("ascii")
        wrong_secret = os.urandom(48).hex().encode("ascii")

        subprocess.run(
            ["truncate", "-s", "96M", str(image)],
            check=True,
        )

        by_id_dir.mkdir(parents=True, exist_ok=True)
        selector.symlink_to(image)

        config = RedPersistenceConfig(device=str(selector))

        try:
            if probe_workspace_state(config) is not RedPersistenceState.UNINITIALIZED:
                raise RuntimeError("fresh disposable workspace was not uninitialized")

            provision_workspace(
                config,
                passphrase=secret,
                destructive_confirmation=True,
            )
            if probe_workspace_state(config) is not RedPersistenceState.MOUNTED:
                raise RuntimeError("provisioned workspace was not mounted")
            state_file.parent.mkdir(parents=True, exist_ok=True)
            state_file.write_text("red-night-persisted\n", encoding="utf-8")
            persisted_hash = sha256(state_file)
            subprocess.run(["sync"], check=True)

            safe_close_workspace(config, mounted=True)
            if mapper.exists():
                raise RuntimeError("mapper remained after safe close")
            if probe_workspace_state(config) is not RedPersistenceState.LUKS2_LOCKED:
                raise RuntimeError("closed workspace was not detected as locked LUKS2")

            unlock_workspace(config, passphrase=secret)
            if probe_workspace_state(config) is not RedPersistenceState.LUKS2_OPEN:
                raise RuntimeError("unlocked workspace was not detected as open")
            mount_workspace(config)
            if probe_workspace_state(config) is not RedPersistenceState.MOUNTED:
                raise RuntimeError("remounted workspace was not detected as mounted")
            if sha256(state_file) != persisted_hash:
                raise RuntimeError("persisted Red workspace state changed")
            safe_close_workspace(config, mounted=True)

            image_hash_before = sha256(image)
            ephemeral = temp / "ephemeral-state.txt"
            ephemeral.write_text("temporary\n", encoding="utf-8")
            if sha256(image) != image_hash_before:
                raise RuntimeError("ephemeral phase modified encrypted workspace")

            try:
                unlock_workspace(config, passphrase=wrong_secret)
            except PersistenceExecutionError:
                pass
            else:
                raise RuntimeError("wrong passphrase unexpectedly unlocked workspace")
            if mapper.exists():
                raise RuntimeError("wrong passphrase created mapper")

            print("RED_NIGHT_LUKS2_EXECUTOR_OK")
            return 0
        finally:
            subprocess.run(["umount", str(mountpoint)], check=False)
            subprocess.run(
                ["/usr/sbin/cryptsetup", "close", WORKSPACE_MAPPER_NAME],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            selector.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
