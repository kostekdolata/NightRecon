"""Red Night Live appliance-session controller.

Batch 3 adds an explicit appliance session around the existing Red Night
application without changing Red engine authorization or assessment behavior.

Secure Workspace remains unavailable until Batch 4's privileged persistence
adapter supplies a mounted encrypted workspace. Ephemeral Session runs Red commands from a temporary
runtime directory. Recovery & Integrity Check validates the installed Red
deployment contract and never launches assessment commands.
"""

from __future__ import annotations

import argparse
import getpass
from dataclasses import dataclass
from enum import Enum
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
from tempfile import TemporaryDirectory
from typing import Callable, Sequence

from .deployment import validate_red_deployment_contract
from .persistence import RedPersistenceConfig, RedPersistenceState, secure_workspace_ready
from .persistence_executor import (
    PersistenceExecutionError,
    mount_workspace,
    probe_workspace_state,
    safe_close_workspace,
    unlock_workspace,
)
from .privilege import require_platform_privilege


AUTHORIZATION_EFFECT = "none"
REQUIRED_OS_PRIVILEGE = "root"


class RedLiveSessionMode(str, Enum):
    SECURE_WORKSPACE = "secure-workspace"
    EPHEMERAL_SESSION = "ephemeral-session"
    RECOVERY_INTEGRITY = "recovery-integrity"


@dataclass(frozen=True)
class RedLiveSessionDecision:
    mode: RedLiveSessionMode
    available: bool
    launch_red_application: bool
    persistent_workspace: bool
    authorization_effect: str
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "mode": self.mode.value,
            "available": self.available,
            "launch_red_application": self.launch_red_application,
            "persistent_workspace": self.persistent_workspace,
            "authorization_effect": self.authorization_effect,
            "reason": self.reason,
        }


def session_decision(
    mode: RedLiveSessionMode | str,
    *,
    persistence_state: RedPersistenceState | str | None = None,
) -> RedLiveSessionDecision:
    selected = RedLiveSessionMode(mode)
    if selected is RedLiveSessionMode.SECURE_WORKSPACE:
        ready = (
            persistence_state is not None
            and secure_workspace_ready(persistence_state)
        )
        return RedLiveSessionDecision(
            mode=selected,
            available=ready,
            launch_red_application=ready,
            persistent_workspace=ready,
            authorization_effect=AUTHORIZATION_EFFECT,
            reason=(
                "encrypted-persistence-mounted"
                if ready
                else "encrypted-persistence-not-mounted"
            ),
        )
    if selected is RedLiveSessionMode.EPHEMERAL_SESSION:
        return RedLiveSessionDecision(
            mode=selected,
            available=True,
            launch_red_application=True,
            persistent_workspace=False,
            authorization_effect=AUTHORIZATION_EFFECT,
            reason="explicit-ephemeral-session",
        )
    return RedLiveSessionDecision(
        mode=selected,
        available=True,
        launch_red_application=False,
        persistent_workspace=False,
        authorization_effect=AUTHORIZATION_EFFECT,
        reason="recovery-integrity-only",
    )


def prompt_for_mode(
    *,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
) -> RedLiveSessionMode:
    choices = {
        "1": RedLiveSessionMode.SECURE_WORKSPACE,
        "2": RedLiveSessionMode.EPHEMERAL_SESSION,
        "3": RedLiveSessionMode.RECOVERY_INTEGRITY,
    }
    while True:
        output_fn("")
        output_fn("Red Night Live")
        output_fn("1. Secure Workspace")
        output_fn("2. Ephemeral Session")
        output_fn("3. Recovery & Integrity Check")
        output_fn("No mode is selected automatically.")
        selected = input_fn("Select mode [1-3]: ").strip()
        if selected in choices:
            return choices[selected]
        output_fn("Invalid selection. Choose 1, 2, or 3.")


def _default_command_runner(args: Sequence[str], cwd: Path) -> int:
    completed = subprocess.run(
        [sys.executable, "-m", "red_night_app", *args],
        cwd=cwd,
        check=False,
    )
    return int(completed.returncode)


def run_ephemeral_operator_session(
    *,
    runtime_root: Path | None = None,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
    command_runner: Callable[[Sequence[str], Path], int] = _default_command_runner,
) -> int:
    base = runtime_root
    if base is None:
        configured_root = os.environ.get("NIGHTRECON_EPHEMERAL_ROOT")
        base = Path(configured_root) if configured_root else None
    if base is not None:
        base.mkdir(parents=True, exist_ok=True)

    with TemporaryDirectory(prefix="red-night-ephemeral-", dir=base) as raw_workspace:
        workspace = Path(raw_workspace)
        output_fn("Ephemeral Session active.")
        output_fn(
            "Red Night commands run from temporary runtime storage. "
            "Active operations still require normal Red/shared-core authorization."
        )
        output_fn("Type 'help' for Red Night CLI help or 'exit' to leave the session.")

        while True:
            try:
                raw = input_fn("red-night> ")
            except EOFError:
                return 0
            command = raw.strip()
            if not command:
                continue
            if command in {"exit", "quit"}:
                return 0
            try:
                args = shlex.split(command)
            except ValueError as exc:
                output_fn(f"Input error: {exc}")
                continue
            if not args:
                continue
            if args == ["help"]:
                args = ["--help"]
            command_runner(args, workspace)


def _read_passphrase(prompt: str) -> bytes:
    value = getpass.getpass(prompt)
    if not value:
        raise ValueError("Secure Workspace passphrase must not be empty")
    return value.encode()


def run_secure_workspace_session(
    config: RedPersistenceConfig,
    *,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
    passphrase_fn: Callable[[str], bytes] = _read_passphrase,
    command_runner: Callable[[Sequence[str], Path], int] = _default_command_runner,
    state_probe: Callable[[RedPersistenceConfig], RedPersistenceState] = probe_workspace_state,
    unlocker: Callable[..., None] = unlock_workspace,
    mounter: Callable[..., None] = mount_workspace,
    closer: Callable[..., None] = safe_close_workspace,
) -> int:
    """Open an existing encrypted workspace and run Red from that mount."""

    state = state_probe(config)
    if state is RedPersistenceState.MISSING:
        output_fn("Secure Workspace device is not present.")
        return 3
    if state is RedPersistenceState.UNINITIALIZED:
        output_fn(
            "Secure Workspace is uninitialized. Explicit provisioning is required "
            "before it can be launched."
        )
        return 3
    if state is RedPersistenceState.LUKS2_OPEN:
        output_fn(
            "Secure Workspace mapping is already open but not mounted; "
            "refusing ambiguous ownership state."
        )
        return 3

    opened_here = False
    if state is RedPersistenceState.LUKS2_LOCKED:
        secret = passphrase_fn("Secure Workspace passphrase: ")
        try:
            unlocker(config, passphrase=secret)
        finally:
            secret = b""
        mounter(config)
        opened_here = True
        state = RedPersistenceState.MOUNTED

    if state is not RedPersistenceState.MOUNTED:
        output_fn("Secure Workspace did not reach a mounted state.")
        return 3

    workspace = Path(config.mount_point)
    output_fn("Secure Workspace active.")
    output_fn(
        "Red Night is running from encrypted persistent storage. "
        "NightRecon authorization controls remain unchanged."
    )
    os.environ["NIGHTRECON_LIVE_MODE"] = RedLiveSessionMode.SECURE_WORKSPACE.value
    os.environ["NIGHTRECON_SECURE_WORKSPACE"] = config.mount_point

    try:
        while True:
            try:
                raw = input_fn("red-night-secure> ")
            except EOFError:
                return 0
            command = raw.strip()
            if not command:
                continue
            if command in {"exit", "quit"}:
                return 0
            try:
                args = shlex.split(command)
            except ValueError as exc:
                output_fn(f"Input error: {exc}")
                continue
            if not args:
                continue
            if args == ["help"]:
                args = ["--help"]
            command_runner(args, workspace)
    finally:
        os.environ.pop("NIGHTRECON_SECURE_WORKSPACE", None)
        if opened_here:
            closer(config, mounted=True)


def run_recovery_integrity_check(
    *,
    output_fn: Callable[[str], None] = print,
) -> int:
    validate_red_deployment_contract()
    output_fn("Recovery & Integrity Check")
    output_fn("Red deployment contract: OK")
    output_fn("Authorization effect: none")
    output_fn("Encrypted persistence contract: available; privileged execution: not enabled.")
    return 0


def require_privileged_runtime() -> None:
    """Fail closed if the Live appliance lacks required platform privilege."""

    require_platform_privilege()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="red-night-appliance",
        description="Explicit Red Night Live appliance-session selector.",
    )
    parser.add_argument(
        "--mode",
        choices=tuple(mode.value for mode in RedLiveSessionMode),
        help="Explicit Live session mode. Omit only for the interactive selector.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the selected session contract as JSON without starting a session.",
    )
    parser.add_argument(
        "--persistence-device",
        help=(
            "Explicit stable Secure Workspace partition selector. "
            "Must use /dev/disk/by-partuuid/... or partition-qualified /dev/disk/by-id/...."
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    mode = (
        RedLiveSessionMode(args.mode)
        if args.mode is not None
        else prompt_for_mode()
    )
    decision = session_decision(mode)

    if args.dry_run:
        print(json.dumps(decision.to_dict(), sort_keys=True))
        return 0

    require_privileged_runtime()

    if mode is RedLiveSessionMode.SECURE_WORKSPACE:
        device = args.persistence_device
        if device is None:
            device = input(
                "Secure Workspace partition "
                "(/dev/disk/by-partuuid/... or /dev/disk/by-id/...-partN): "
            ).strip()
        try:
            config = RedPersistenceConfig(device=device)
            return run_secure_workspace_session(config)
        except (ValueError, PersistenceExecutionError) as exc:
            print(f"Secure Workspace unavailable: {exc}")
            print("No Red assessment session was started.")
            return 3

    if mode is RedLiveSessionMode.RECOVERY_INTEGRITY:
        return run_recovery_integrity_check()

    os.environ["NIGHTRECON_LIVE_MODE"] = mode.value
    return run_ephemeral_operator_session()


if __name__ == "__main__":
    raise SystemExit(main())
