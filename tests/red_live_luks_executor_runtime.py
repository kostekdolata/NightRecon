"""Disposable Red Night encrypted-workspace lifecycle integration fixture.

CI creates a regular-file LUKS2 container and exposes it through a temporary
/dev/disk/by-id/...-part1 selector. The test proves first-use provisioning,
a fresh-process reboot boundary, persisted state recovery, real Ephemeral
Session isolation, wrong-secret rejection, and cleanup without touching a
physical host disk.
"""

from __future__ import annotations

import argparse
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

from red_night_app.appliance import (  # noqa: E402
    run_ephemeral_operator_session,
    run_recovery_integrity_check,
)
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
    for name in ("cryptsetup", "mkfs.ext4", "mount", "umount", "mountpoint"):
        if shutil.which(name) is None:
            raise SystemExit(f"required command not found: {name}")


def read_secret_from_stdin() -> bytes:
    secret = sys.stdin.buffer.readline().rstrip(b"\n")
    if not secret or b"\x00" in secret:
        raise RuntimeError("invalid reboot verification secret")
    return secret


def verify_reboot_phase(selector: str, expected_hash: str) -> int:
    """Act as a fresh boot/process and verify the encrypted workspace."""

    require_root()
    require_tools()
    config = RedPersistenceConfig(device=selector)
    state_file = Path(WORKSPACE_MOUNT_POINT) / "engagements" / "ci-state.txt"
    reboot_file = Path(WORKSPACE_MOUNT_POINT) / "engagements" / "ci-reboot.txt"
    secret = read_secret_from_stdin()

    if probe_workspace_state(config) is not RedPersistenceState.LUKS2_LOCKED:
        raise RuntimeError("reboot phase did not begin from locked LUKS2 state")

    try:
        unlock_workspace(config, passphrase=secret)
        if probe_workspace_state(config) is not RedPersistenceState.LUKS2_OPEN:
            raise RuntimeError("reboot phase did not observe open LUKS2 mapping")
        mount_workspace(config)
        if probe_workspace_state(config) is not RedPersistenceState.MOUNTED:
            raise RuntimeError("reboot phase did not mount Secure Workspace")
        if not state_file.is_file() or sha256(state_file) != expected_hash:
            raise RuntimeError("persisted Red workspace state did not survive reboot boundary")

        reboot_file.write_text("fresh-process-reboot-verified\n", encoding="utf-8")
        subprocess.run(["sync"], check=True)
    finally:
        if probe_workspace_state(config) is RedPersistenceState.MOUNTED:
            safe_close_workspace(config, mounted=True)
        elif probe_workspace_state(config) is RedPersistenceState.LUKS2_OPEN:
            safe_close_workspace(config, mounted=False)

    if probe_workspace_state(config) is not RedPersistenceState.LUKS2_LOCKED:
        raise RuntimeError("reboot phase did not safely return workspace to locked state")

    print("RED_NIGHT_REBOOT_PERSISTENCE_OK")
    return 0


def run_fixture() -> int:
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
        reboot_file = mountpoint / "engagements" / "ci-reboot.txt"
        secret = os.urandom(48).hex().encode("ascii")
        wrong_secret = os.urandom(48).hex().encode("ascii")

        subprocess.run(["truncate", "-s", "96M", str(image)], check=True)

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
                raise RuntimeError("mapper remained after initial safe close")
            if probe_workspace_state(config) is not RedPersistenceState.LUKS2_LOCKED:
                raise RuntimeError("initial close did not leave locked LUKS2 workspace")

            reboot = subprocess.run(
                [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "--verify-reboot",
                    str(selector),
                    persisted_hash,
                ],
                input=secret + b"\n",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            if reboot.returncode != 0:
                raise RuntimeError(
                    "fresh-process reboot verification failed: "
                    + reboot.stderr.decode("utf-8", errors="replace")
                )
            if b"RED_NIGHT_REBOOT_PERSISTENCE_OK" not in reboot.stdout:
                raise RuntimeError("fresh-process reboot verification marker missing")
            if mapper.exists():
                raise RuntimeError("fresh-process reboot phase left mapper open")
            if probe_workspace_state(config) is not RedPersistenceState.LUKS2_LOCKED:
                raise RuntimeError("workspace was not locked after reboot verification")

            image_hash_before_removal = sha256(image)
            recovery_output: list[str] = []
            recovery_code = run_recovery_integrity_check(
                config=config,
                output_fn=recovery_output.append,
            )
            if recovery_code != 0:
                raise RuntimeError("Recovery & Integrity inspection returned non-zero")
            if "Persistence state: luks2-locked" not in recovery_output:
                raise RuntimeError("Recovery & Integrity did not report locked LUKS2")
            if "Safe removal ready: yes" not in recovery_output:
                raise RuntimeError("Recovery & Integrity did not report safe removal readiness")
            if sha256(image) != image_hash_before_removal:
                raise RuntimeError("Recovery & Integrity modified encrypted workspace image")
            if mapper.exists():
                raise RuntimeError("Recovery & Integrity unexpectedly opened workspace mapper")

            selector.unlink()
            if probe_workspace_state(config) is not RedPersistenceState.MISSING:
                raise RuntimeError("removed persistence selector was not reported missing")
            if mapper.exists():
                raise RuntimeError("mapper remained open during simulated safe removal")
            mounted = subprocess.run(
                ["mountpoint", "-q", str(mountpoint)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            if mounted.returncode == 0:
                raise RuntimeError("workspace mount remained active during simulated removal")

            selector.symlink_to(image)
            if probe_workspace_state(config) is not RedPersistenceState.LUKS2_LOCKED:
                raise RuntimeError("reattached encrypted workspace was not detected as locked")

            unlock_workspace(config, passphrase=secret)
            mount_workspace(config)
            if sha256(state_file) != persisted_hash:
                raise RuntimeError("persisted state changed across safe removal and reattach")
            if reboot_file.read_text(encoding="utf-8") != "fresh-process-reboot-verified\n":
                raise RuntimeError("reboot marker changed across safe removal and reattach")
            safe_close_workspace(config, mounted=True)
            if probe_workspace_state(config) is not RedPersistenceState.LUKS2_LOCKED:
                raise RuntimeError("reattached workspace did not return to safe locked state")
            print("RED_NIGHT_SAFE_REMOVAL_RECOVERY_OK")

            image_hash_before_ephemeral = sha256(image)
            ephemeral_paths: list[Path] = []
            inputs = iter(["ci-ephemeral-write", "exit"])

            def ephemeral_runner(args, cwd):
                ephemeral_paths.append(cwd)
                if tuple(args) != ("ci-ephemeral-write",):
                    raise RuntimeError("unexpected Ephemeral Session command")
                (cwd / "ephemeral-state.txt").write_text(
                    "temporary-only\n",
                    encoding="utf-8",
                )
                return 0

            ephemeral_root = temp / "ephemeral-runtime"
            result = run_ephemeral_operator_session(
                runtime_root=ephemeral_root,
                input_fn=lambda _prompt: next(inputs),
                output_fn=lambda _message: None,
                command_runner=ephemeral_runner,
            )
            if result != 0:
                raise RuntimeError("Ephemeral Session returned non-zero status")
            if not ephemeral_paths:
                raise RuntimeError("Ephemeral Session did not execute its command")
            if any(path.exists() for path in ephemeral_paths):
                raise RuntimeError("Ephemeral Session workspace survived session exit")
            if sha256(image) != image_hash_before_ephemeral:
                raise RuntimeError("Ephemeral Session modified encrypted workspace image")
            if probe_workspace_state(config) is not RedPersistenceState.LUKS2_LOCKED:
                raise RuntimeError("Ephemeral Session changed encrypted workspace state")
            print("RED_NIGHT_EPHEMERAL_ISOLATION_OK")

            unlock_workspace(config, passphrase=secret)
            mount_workspace(config)
            if sha256(state_file) != persisted_hash:
                raise RuntimeError("persisted Red workspace state changed after Ephemeral Session")
            if reboot_file.read_text(encoding="utf-8") != "fresh-process-reboot-verified\n":
                raise RuntimeError("fresh-process reboot marker did not persist")
            safe_close_workspace(config, mounted=True)

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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify-reboot", action="store_true")
    parser.add_argument("selector", nargs="?")
    parser.add_argument("expected_hash", nargs="?")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.verify_reboot:
        if not args.selector or not args.expected_hash:
            raise SystemExit("--verify-reboot requires selector and expected_hash")
        return verify_reboot_phase(args.selector, args.expected_hash)
    if args.selector is not None or args.expected_hash is not None:
        raise SystemExit("unexpected positional arguments")
    return run_fixture()


if __name__ == "__main__":
    raise SystemExit(main())
