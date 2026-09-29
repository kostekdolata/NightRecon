"""Network-free White Night package capability declaration."""

from __future__ import annotations

WHITE_EDITION_SLUG = "white"

# Batch 2 is deliberately informational only. The command manifest is explicit
# so tests can prove the package has not accidentally acquired active commands.
WHITE_OWNED_COMMANDS: tuple[str, ...] = ("editions",)
WHITE_ACTIVE_COMMANDS: tuple[str, ...] = ()

WHITE_FOUNDATION_CAPABILITIES: tuple[str, ...] = (
    "independent-package-boundary",
    "shared-core-policy-consumer",
    "standalone-deployment-target",
    "composed-stack-deployment-target",
    "live-usb-deployment-target",
)
