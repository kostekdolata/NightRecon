"""Evidence-honest production deployment acceptance records for Red Night."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RedHardwareQualification:
    hardware_id: str
    uefi_boot_verified: bool
    secure_workspace_verified: bool
    ephemeral_session_verified: bool
    recovery_verified: bool
    network_verified: bool

    def __post_init__(self) -> None:
        if not self.hardware_id or self.hardware_id != self.hardware_id.strip():
            raise ValueError("hardware_id must be a nonblank trimmed string")

    @property
    def passed(self) -> bool:
        return all((
            self.uefi_boot_verified,
            self.secure_workspace_verified,
            self.ephemeral_session_verified,
            self.recovery_verified,
            self.network_verified,
        ))


@dataclass(frozen=True)
class RedEnduranceQualification:
    media_id: str
    continuous_hours: int
    reboot_cycles: int
    safe_remove_cycles: int
    integrity_failures: int

    def __post_init__(self) -> None:
        if not self.media_id or self.media_id != self.media_id.strip():
            raise ValueError("media_id must be a nonblank trimmed string")
        for value, field in (
            (self.continuous_hours, "continuous_hours"),
            (self.reboot_cycles, "reboot_cycles"),
            (self.safe_remove_cycles, "safe_remove_cycles"),
            (self.integrity_failures, "integrity_failures"),
        ):
            if not isinstance(value, int) or value < 0:
                raise ValueError(f"{field} must be a non-negative integer")

    @property
    def passed(self) -> bool:
        return (
            self.continuous_hours >= 24
            and self.reboot_cycles >= 20
            and self.safe_remove_cycles >= 20
            and self.integrity_failures == 0
        )


@dataclass(frozen=True)
class RedDeploymentReadiness:
    automated_gates_green: bool
    secure_boot_verified: bool
    hardware_qualifications: tuple[RedHardwareQualification, ...]
    endurance_qualifications: tuple[RedEnduranceQualification, ...]
    blockers: tuple[str, ...]
    ready_for_production_deployment: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "automated_gates_green": self.automated_gates_green,
            "secure_boot_verified": self.secure_boot_verified,
            "hardware_qualifications": [
                {
                    "hardware_id": item.hardware_id,
                    "passed": item.passed,
                }
                for item in self.hardware_qualifications
            ],
            "endurance_qualifications": [
                {
                    "media_id": item.media_id,
                    "passed": item.passed,
                    "continuous_hours": item.continuous_hours,
                    "reboot_cycles": item.reboot_cycles,
                    "safe_remove_cycles": item.safe_remove_cycles,
                    "integrity_failures": item.integrity_failures,
                }
                for item in self.endurance_qualifications
            ],
            "blockers": list(self.blockers),
            "ready_for_production_deployment": self.ready_for_production_deployment,
        }


def evaluate_red_deployment_readiness(
    *,
    automated_gates_green: bool,
    secure_boot_verified: bool,
    hardware_qualifications: tuple[RedHardwareQualification, ...],
    endurance_qualifications: tuple[RedEnduranceQualification, ...],
) -> RedDeploymentReadiness:
    blockers: list[str] = []
    if not automated_gates_green:
        blockers.append("automated release/deployment gates are not green")
    if not secure_boot_verified:
        blockers.append("Secure Boot has not been verified")
    if not hardware_qualifications:
        blockers.append("hardware compatibility matrix has no verified entries")
    elif not all(item.passed for item in hardware_qualifications):
        blockers.append("one or more hardware compatibility entries failed")
    if not endurance_qualifications:
        blockers.append("USB endurance qualification has not been recorded")
    elif not all(item.passed for item in endurance_qualifications):
        blockers.append("one or more USB endurance qualifications failed")

    return RedDeploymentReadiness(
        automated_gates_green=automated_gates_green,
        secure_boot_verified=secure_boot_verified,
        hardware_qualifications=hardware_qualifications,
        endurance_qualifications=endurance_qualifications,
        blockers=tuple(blockers),
        ready_for_production_deployment=not blockers,
    )
