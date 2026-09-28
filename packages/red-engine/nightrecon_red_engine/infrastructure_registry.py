"""Built-in read-only credentialed infrastructure action registry."""

from __future__ import annotations

from nightrecon_red_engine.infrastructure_models import (
    InfrastructureActionCategory,
    InfrastructureActionDefinition,
    InfrastructureTransport,
)


_BUILTIN_ACTIONS = (
    InfrastructureActionDefinition(
        action_id="ssh.system_identity",
        transport=InfrastructureTransport.SSH,
        category=InfrastructureActionCategory.IDENTITY,
        description="Observe remote system identity metadata.",
    ),
    InfrastructureActionDefinition(
        action_id="ssh.os_inventory",
        transport=InfrastructureTransport.SSH,
        category=InfrastructureActionCategory.INVENTORY,
        description="Observe operating-system inventory metadata.",
    ),
    InfrastructureActionDefinition(
        action_id="smb.server_identity",
        transport=InfrastructureTransport.SMB,
        category=InfrastructureActionCategory.IDENTITY,
        description="Observe SMB server identity metadata.",
    ),
    InfrastructureActionDefinition(
        action_id="smb.share_inventory",
        transport=InfrastructureTransport.SMB,
        category=InfrastructureActionCategory.INVENTORY,
        description="Observe available share metadata.",
    ),
    InfrastructureActionDefinition(
        action_id="winrm.system_identity",
        transport=InfrastructureTransport.WINRM,
        category=InfrastructureActionCategory.IDENTITY,
        description="Observe Windows system identity metadata.",
    ),
    InfrastructureActionDefinition(
        action_id="winrm.patch_inventory",
        transport=InfrastructureTransport.WINRM,
        category=InfrastructureActionCategory.PATCH,
        description="Observe installed patch inventory metadata.",
    ),
    InfrastructureActionDefinition(
        action_id="database.server_identity",
        transport=InfrastructureTransport.DATABASE,
        category=InfrastructureActionCategory.IDENTITY,
        description="Observe database server identity/version metadata.",
    ),
    InfrastructureActionDefinition(
        action_id="database.schema_inventory",
        transport=InfrastructureTransport.DATABASE,
        category=InfrastructureActionCategory.INVENTORY,
        description="Observe database schema inventory metadata.",
    ),
    InfrastructureActionDefinition(
        action_id="network_device.system_identity",
        transport=InfrastructureTransport.NETWORK_DEVICE,
        category=InfrastructureActionCategory.IDENTITY,
        description="Observe network-device system identity metadata.",
    ),
    InfrastructureActionDefinition(
        action_id="network_device.interface_inventory",
        transport=InfrastructureTransport.NETWORK_DEVICE,
        category=InfrastructureActionCategory.INVENTORY,
        description="Observe network-device interface state metadata.",
    ),
)


def built_in_infrastructure_actions(
) -> tuple[InfrastructureActionDefinition, ...]:
    """Return the immutable built-in read-only action registry."""

    return _BUILTIN_ACTIONS


def get_infrastructure_action_definition(
    action_id: str,
) -> InfrastructureActionDefinition:
    """Resolve one exact symbolic action ID."""

    normalized = action_id.strip()

    if not normalized:
        raise ValueError(
            "action_id must be non-empty."
        )

    matches = tuple(
        item
        for item in _BUILTIN_ACTIONS
        if item.action_id
        == normalized
    )

    if len(matches) != 1:
        raise ValueError(
            f"Unknown infrastructure action: {normalized}"
        )

    return matches[0]
