"""Red Night Live appliance-session controller.

Batch 3 adds an explicit appliance session around the existing Red Night
application without changing Red engine authorization or assessment behavior.

Secure Workspace remains unavailable until Batch 4 provides the encrypted
persistent workspace. Ephemeral Session runs Red commands from a temporary
runtime directory. Recovery & Integrity Check validates the installed Red
deployment contract and never launches assessment commands.
"""

from __future__ import annotations

import argparse
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


AUTHORIZATION_EFFECT = "none"


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


def session_decision(mode: RedLiveSessionMode | str) -> RedLiveSessionDecision:
    selected = RedLiveSessionMode(mode)
    if selected is RedLiveSessionMode.SECURE_WORKSPACE:
        return RedLiveSessionDecision(
            mode=selected,
            available=False,
            launch_red_application=False,
            persistent_workspace=False,
            authorization_effect=AUTHORIZATION_EFFECT,
            reason="encrypted-persistence-not-available-until-batch-4",
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
    base = runtime_root if runtime_root is not None else Path("/run")
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


def run_recovery_integrity_check(
    *,
    output_fn: Callable[[str], None] = print,
) -> int:
    validate_red_deployment_contract()
    output_fn("Recovery & Integrity Check")
    output_fn("Red deployment contract: OK")
    output_fn("Authorization effect: none")
    output_fn("Encrypted persistence diagnostics arrive in Batch 4.")
    return 0


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

    if mode is RedLiveSessionMode.SECURE_WORKSPACE:
        print("Secure Workspace is not available yet.")
        print("Batch 4 must provide and unlock the encrypted LUKS2 workspace first.")
        print("No Red assessment session was started.")
        return 3

    if mode is RedLiveSessionMode.RECOVERY_INTEGRITY:
        return run_recovery_integrity_check()

    os.environ["NIGHTRECON_LIVE_MODE"] = mode.value
    return run_ephemeral_operator_session()


if __name__ == "__main__":
    raise SystemExit(main())
