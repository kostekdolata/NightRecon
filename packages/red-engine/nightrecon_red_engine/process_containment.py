"""Cross-platform child-process containment interface.

POSIX uses an isolated process group. Windows containment requires an
external Job Object supervisor and deliberately fails closed if unavailable.
No admin elevation or arbitrary shell execution is provided.
"""
from __future__ import annotations
from dataclasses import dataclass
import os
import signal
import subprocess

@dataclass(frozen=True)
class ContainmentCapabilities:
    platform: str
    process_tree_termination: bool
    reason: str

def containment_capabilities() -> ContainmentCapabilities:
    if os.name == "posix":
        return ContainmentCapabilities("posix", True, "isolated process group")
    return ContainmentCapabilities(os.name, False, "Windows Job Object supervisor required")

def terminate_contained_process(process: subprocess.Popen) -> None:
    """Fail closed rather than claiming Windows descendants were stopped."""
    if os.name != "posix":
        raise RuntimeError("Process tree containment unavailable on this platform")
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=5)
