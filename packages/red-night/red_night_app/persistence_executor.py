"""Narrow privileged executor for Red Night Live LUKS2 persistence.

The executor consumes only plans produced by red_night_app.persistence.  It does
not discover disks, choose targets, or infer state.  Commands are passed as
argument vectors with shell=False semantics; passphrases are supplied only on
stdin and are never included in argv, return values, or exception text.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
import subprocess
from typing import Callable, Sequence

from .persistence import (
    RedPersistenceAction,
    RedPersistenceConfig,
    RedPersistencePlan,
    RedPersistenceStep,
    plan_persistence_action,
)


CRYPTSETUP = "/usr/sbin/cryptsetup"
MKFS_EXT4 = "/usr/sbin/mkfs.ext4"
MOUNT = "/usr/bin/mount"
UMOUNT = "/usr/bin/umount"
INSTALL = "/usr/bin/install"
BLKID = "/usr/sbin/blkid"


@dataclass(frozen=True)
class PrivilegedCommandResult:
    returncode: int


CommandRunner = Callable[[Sequence[str], bytes | None], PrivilegedCommandResult]
TargetProbe = Callable[[str], bool]


class PersistenceExecutionError(RuntimeError):
    """Raised for a failed privileged persistence step without leaking secrets."""


def _default_runner(
    argv: Sequence[str],
    stdin_bytes: bytes | None,
) -> PrivilegedCommandResult:
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None or geteuid() != 0:
        raise PermissionError("privileged persistence execution requires root")

    completed = subprocess.run(
        list(argv),
        input=stdin_bytes,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return PrivilegedCommandResult(returncode=int(completed.returncode))


def _default_uninitialized_probe(device: str) -> bool:
    """Return true only when blkid finds no existing on-disk signature."""

    geteuid = getattr(os, "geteuid", None)
    if geteuid is None or geteuid() != 0:
        raise PermissionError("persistence target inspection requires root")
    if not os.path.exists(device):
        return False

    completed = subprocess.run(
        [BLKID, "-p", device],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if completed.returncode == 2:
        return True
    if completed.returncode == 0:
        return False
    raise PersistenceExecutionError("unable to verify persistence target is empty")


def _validate_plan(
    config: RedPersistenceConfig,
    plan: RedPersistencePlan,
) -> None:
    expected = plan_persistence_action(
        config,
        state=plan.from_state,
        action=plan.action,
        destructive_confirmation=plan.destructive,
    )
    if plan != expected or not plan.allowed:
        raise ValueError("persistence plan is not an allowed canonical plan")


def _require_passphrase(plan: RedPersistencePlan, passphrase: bytes | None) -> None:
    if plan.requires_passphrase:
        if not isinstance(passphrase, bytes) or not passphrase:
            raise ValueError("non-empty passphrase bytes are required")
        if b"\x00" in passphrase:
            raise ValueError("passphrase must not contain NUL bytes")
    elif passphrase is not None:
        raise ValueError("passphrase supplied for a plan that does not require one")


def _run(
    runner: CommandRunner,
    argv: Sequence[str],
    stdin_bytes: bytes | None = None,
) -> None:
    result = runner(tuple(argv), stdin_bytes)
    if result.returncode != 0:
        raise PersistenceExecutionError(
            f"privileged persistence command failed: {argv[0]}"
        )


def execute_persistence_plan(
    config: RedPersistenceConfig,
    plan: RedPersistencePlan,
    *,
    passphrase: bytes | None = None,
    runner: CommandRunner = _default_runner,
) -> None:
    """Execute one canonical persistence plan in fixed step order."""

    _validate_plan(config, plan)
    _require_passphrase(plan, passphrase)

    mapper_device = f"/dev/mapper/{config.mapper_name}"

    for step in plan.steps:
        if step is RedPersistenceStep.LUKS2_FORMAT:
            _run(
                runner,
                (
                    CRYPTSETUP,
                    "luksFormat",
                    "--type",
                    "luks2",
                    "--batch-mode",
                    "--key-file",
                    "-",
                    config.device,
                ),
                passphrase,
            )
        elif step is RedPersistenceStep.LUKS2_OPEN:
            _run(
                runner,
                (
                    CRYPTSETUP,
                    "open",
                    "--type",
                    "luks2",
                    "--key-file",
                    "-",
                    config.device,
                    config.mapper_name,
                ),
                passphrase,
            )
        elif step is RedPersistenceStep.FILESYSTEM_CREATE:
            _run(
                runner,
                (
                    MKFS_EXT4,
                    "-F",
                    "-L",
                    "RED_NIGHT_WORKSPACE",
                    mapper_device,
                ),
            )
        elif step is RedPersistenceStep.FILESYSTEM_MOUNT:
            _run(
                runner,
                (INSTALL, "-d", "-m", "0700", config.mount_point),
            )
            _run(
                runner,
                (
                    MOUNT,
                    "-t",
                    config.filesystem,
                    "-o",
                    "nosuid,nodev",
                    mapper_device,
                    config.mount_point,
                ),
            )
        elif step is RedPersistenceStep.FILESYSTEM_UNMOUNT:
            _run(runner, (UMOUNT, config.mount_point))
        elif step is RedPersistenceStep.LUKS2_CLOSE:
            _run(runner, (CRYPTSETUP, "close", config.mapper_name))
        else:
            raise ValueError(f"unsupported persistence step: {step!r}")


def provision_workspace(
    config: RedPersistenceConfig,
    *,
    passphrase: bytes,
    destructive_confirmation: bool,
    runner: CommandRunner = _default_runner,
    target_probe: TargetProbe = _default_uninitialized_probe,
) -> None:
    plan = plan_persistence_action(
        config,
        state="uninitialized",
        action=RedPersistenceAction.PROVISION,
        destructive_confirmation=destructive_confirmation,
    )
    if not plan.allowed:
        execute_persistence_plan(
            config,
            plan,
            passphrase=passphrase,
            runner=runner,
        )
        return

    if not target_probe(config.device):
        raise ValueError("persistence target is not verified empty")

    execute_persistence_plan(
        config,
        plan,
        passphrase=passphrase,
        runner=runner,
    )


def unlock_workspace(
    config: RedPersistenceConfig,
    *,
    passphrase: bytes,
    runner: CommandRunner = _default_runner,
) -> None:
    plan = plan_persistence_action(
        config,
        state="luks2-locked",
        action=RedPersistenceAction.UNLOCK,
    )
    execute_persistence_plan(
        config,
        plan,
        passphrase=passphrase,
        runner=runner,
    )


def mount_workspace(
    config: RedPersistenceConfig,
    *,
    runner: CommandRunner = _default_runner,
) -> None:
    plan = plan_persistence_action(
        config,
        state="luks2-open",
        action=RedPersistenceAction.MOUNT,
    )
    execute_persistence_plan(config, plan, runner=runner)


def safe_close_workspace(
    config: RedPersistenceConfig,
    *,
    mounted: bool,
    runner: CommandRunner = _default_runner,
) -> None:
    state = "mounted" if mounted else "luks2-open"
    plan = plan_persistence_action(
        config,
        state=state,
        action=RedPersistenceAction.SAFE_CLOSE,
    )
    execute_persistence_plan(config, plan, runner=runner)
