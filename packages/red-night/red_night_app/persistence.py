"""Fail-closed Red Night Live encrypted-persistence contracts.

This Batch 4 foundation is intentionally declarative.  It defines the state
machine and privileged-operation boundary for a future LUKS2 workspace without
executing cryptsetup, filesystem, mount, or block-device commands.

A later execution adapter must consume these plans explicitly.  Nothing in this
module discovers disks, formats media, opens mappings, or mounts filesystems.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import PurePosixPath


LUKS_TYPE = "luks2"
WORKSPACE_FILESYSTEM = "ext4"
WORKSPACE_MAPPER_NAME = "red-night-workspace"
WORKSPACE_MOUNT_POINT = "/run/red-night-secure"

_ALLOWED_DEVICE_PREFIXES = (
    "/dev/disk/by-partuuid/",
    "/dev/disk/by-id/",
)


class RedPersistenceState(str, Enum):
    """Observed state of the explicitly selected persistence partition."""

    MISSING = "missing"
    UNINITIALIZED = "uninitialized"
    LUKS2_LOCKED = "luks2-locked"
    LUKS2_OPEN = "luks2-open"
    MOUNTED = "mounted"


class RedPersistenceAction(str, Enum):
    """Operator-requested persistence transition."""

    PROVISION = "provision"
    UNLOCK = "unlock"
    MOUNT = "mount"
    SAFE_CLOSE = "safe-close"


class RedPersistenceStep(str, Enum):
    """Symbolic privileged steps.  No shell commands live in this contract."""

    LUKS2_FORMAT = "luks2-format"
    LUKS2_OPEN = "luks2-open"
    FILESYSTEM_CREATE = "filesystem-create"
    FILESYSTEM_MOUNT = "filesystem-mount"
    FILESYSTEM_UNMOUNT = "filesystem-unmount"
    LUKS2_CLOSE = "luks2-close"


@dataclass(frozen=True)
class RedPersistenceConfig:
    """Immutable configuration for one explicitly selected workspace partition."""

    device: str
    mapper_name: str = WORKSPACE_MAPPER_NAME
    mount_point: str = WORKSPACE_MOUNT_POINT
    luks_type: str = LUKS_TYPE
    filesystem: str = WORKSPACE_FILESYSTEM
    auto_discover: bool = False
    auto_format: bool = False
    auto_mount: bool = False

    def __post_init__(self) -> None:
        if not self.device:
            raise ValueError("persistence device must be explicit")
        if not self.device.startswith(_ALLOWED_DEVICE_PREFIXES):
            raise ValueError(
                "persistence device must use /dev/disk/by-partuuid or /dev/disk/by-id"
            )
        if self.device in _ALLOWED_DEVICE_PREFIXES:
            raise ValueError("persistence device selector is incomplete")
        if self.device.startswith("/dev/disk/by-id/") and "-part" not in self.device:
            raise ValueError("by-id persistence selector must name a partition")
        if self.mapper_name != WORKSPACE_MAPPER_NAME:
            raise ValueError("Red Live mapper name is fixed")
        if self.mount_point != WORKSPACE_MOUNT_POINT:
            raise ValueError("Red Live workspace mount point is fixed")
        if PurePosixPath(self.mount_point).parts[:2] != ("/", "run"):
            raise ValueError("workspace mount point must remain under /run")
        if self.luks_type != LUKS_TYPE:
            raise ValueError("Red Live persistent workspace must use LUKS2")
        if self.filesystem != WORKSPACE_FILESYSTEM:
            raise ValueError("Red Live persistent workspace filesystem is fixed")
        if self.auto_discover or self.auto_format or self.auto_mount:
            raise ValueError("persistence automation must remain disabled")


@dataclass(frozen=True)
class RedPersistencePlan:
    action: RedPersistenceAction
    from_state: RedPersistenceState
    allowed: bool
    destructive: bool
    requires_passphrase: bool
    steps: tuple[RedPersistenceStep, ...]
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "action": self.action.value,
            "from_state": self.from_state.value,
            "allowed": self.allowed,
            "destructive": self.destructive,
            "requires_passphrase": self.requires_passphrase,
            "steps": [step.value for step in self.steps],
            "reason": self.reason,
        }


def plan_persistence_action(
    config: RedPersistenceConfig,
    *,
    state: RedPersistenceState | str,
    action: RedPersistenceAction | str,
    destructive_confirmation: bool = False,
) -> RedPersistencePlan:
    """Plan one explicit persistence transition without touching the system."""

    # Re-validate an externally supplied config even though the dataclass already
    # checks on construction.  This keeps the planner boundary fail-closed.
    RedPersistenceConfig(
        device=config.device,
        mapper_name=config.mapper_name,
        mount_point=config.mount_point,
        luks_type=config.luks_type,
        filesystem=config.filesystem,
        auto_discover=config.auto_discover,
        auto_format=config.auto_format,
        auto_mount=config.auto_mount,
    )

    current = RedPersistenceState(state)
    requested = RedPersistenceAction(action)

    if current is RedPersistenceState.MISSING:
        return RedPersistencePlan(
            requested,
            current,
            False,
            False,
            False,
            (),
            "explicit-persistence-device-not-present",
        )

    if requested is RedPersistenceAction.PROVISION:
        if current is not RedPersistenceState.UNINITIALIZED:
            return RedPersistencePlan(
                requested,
                current,
                False,
                True,
                True,
                (),
                "provision-requires-uninitialized-partition",
            )
        if not destructive_confirmation:
            return RedPersistencePlan(
                requested,
                current,
                False,
                True,
                True,
                (),
                "explicit-destructive-confirmation-required",
            )
        return RedPersistencePlan(
            requested,
            current,
            True,
            True,
            True,
            (
                RedPersistenceStep.LUKS2_FORMAT,
                RedPersistenceStep.LUKS2_OPEN,
                RedPersistenceStep.FILESYSTEM_CREATE,
                RedPersistenceStep.FILESYSTEM_MOUNT,
            ),
            "explicit-first-use-provisioning",
        )

    if requested is RedPersistenceAction.UNLOCK:
        if current is not RedPersistenceState.LUKS2_LOCKED:
            return RedPersistencePlan(
                requested,
                current,
                False,
                False,
                True,
                (),
                "unlock-requires-locked-luks2-workspace",
            )
        return RedPersistencePlan(
            requested,
            current,
            True,
            False,
            True,
            (RedPersistenceStep.LUKS2_OPEN,),
            "explicit-workspace-unlock",
        )

    if requested is RedPersistenceAction.MOUNT:
        if current is not RedPersistenceState.LUKS2_OPEN:
            return RedPersistencePlan(
                requested,
                current,
                False,
                False,
                False,
                (),
                "mount-requires-open-luks2-mapping",
            )
        return RedPersistencePlan(
            requested,
            current,
            True,
            False,
            False,
            (RedPersistenceStep.FILESYSTEM_MOUNT,),
            "explicit-workspace-mount",
        )

    if current is RedPersistenceState.MOUNTED:
        steps = (
            RedPersistenceStep.FILESYSTEM_UNMOUNT,
            RedPersistenceStep.LUKS2_CLOSE,
        )
    elif current is RedPersistenceState.LUKS2_OPEN:
        steps = (RedPersistenceStep.LUKS2_CLOSE,)
    else:
        steps = ()

    return RedPersistencePlan(
        requested,
        current,
        True,
        False,
        False,
        steps,
        "safe-close-ordered",
    )


def secure_workspace_ready(state: RedPersistenceState | str) -> bool:
    """Return true only for a mounted encrypted persistent workspace."""

    return RedPersistenceState(state) is RedPersistenceState.MOUNTED
