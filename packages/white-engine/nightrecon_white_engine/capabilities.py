"""Network-free White Night package capability declaration."""

from __future__ import annotations

WHITE_EDITION_SLUG = "white"

# White owns local policy compilation from Batch 4. It remains network-free and
# does not publish, approve, persist, or execute the resulting policy.
WHITE_OWNED_COMMANDS: tuple[str, ...] = ("approval", "editions", "policy")
WHITE_ACTIVE_COMMANDS: tuple[str, ...] = ()

WHITE_FOUNDATION_CAPABILITIES: tuple[str, ...] = (
    "independent-package-boundary",
    "shared-core-policy-consumer",
    "standalone-deployment-target",
    "composed-stack-deployment-target",
    "live-usb-deployment-target",
    "deterministic-policy-compiler",
    "approval-workflow-engine",
)
