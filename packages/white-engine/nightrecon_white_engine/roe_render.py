"""Deterministic human-readable White Night Rules of Engagement rendering."""

from __future__ import annotations

from nightrecon_white_engine.engagement_domain import (
    EngagementDefinition,
    RulesOfEngagement,
)


def render_rules_of_engagement(roe: RulesOfEngagement) -> str:
    """Render the immutable ROE as stable plain text.

    This output is explanatory. It is not an executable authorization policy.
    """

    allowed = "\n".join(f"- {item}" for item in roe.scope.allowed)
    excluded = (
        "\n".join(f"- {item}" for item in roe.scope.excluded)
        if roe.scope.excluded
        else "- None"
    )
    techniques = "\n".join(f"- {item}" for item in roe.allowed_techniques)
    prohibited = (
        "\n".join(f"- {item}" for item in roe.prohibited_techniques)
        if roe.prohibited_techniques
        else "- None"
    )
    deviation = "required" if roe.deviation_requires_approval else "not required"
    notes = roe.notes or "None"

    return (
        f"RULES OF ENGAGEMENT\n"
        f"Title: {roe.title}\n"
        f"Engagement ID: {roe.engagement_id}\n"
        f"ROE Version: {roe.version}\n"
        f"ROE Fingerprint: {roe.fingerprint}\n"
        f"Created: {roe.created_at}\n"
        f"Valid From: {roe.valid_from}\n"
        f"Valid Until: {roe.valid_until}\n"
        f"Maximum Intrusiveness: {roe.max_intrusiveness}\n"
        f"Maximum Actions: {roe.max_actions}\n"
        f"Deviation Approval: {deviation}\n"
        f"Data Classification: {roe.data_handling.classification}\n"
        f"Retention Days: {roe.data_handling.retention_days}\n"
        f"Export Allowed: {'yes' if roe.data_handling.export_allowed else 'no'}\n"
        f"\nALLOWED SCOPE\n{allowed}\n"
        f"\nEXCLUSIONS\n{excluded}\n"
        f"\nALLOWED TECHNIQUES\n{techniques}\n"
        f"\nPROHIBITED TECHNIQUES\n{prohibited}\n"
        f"\nNOTES\n{notes}\n"
        f"\nNOTICE\n"
        f"This document describes engagement intent and does not itself authorize "
        f"active operations. NightRecon shared-core policy enforcement remains "
        f"authoritative.\n"
    )


def render_engagement_summary(engagement: EngagementDefinition) -> str:
    """Render stable engagement metadata plus its current ROE."""

    owner = next(
        contact for contact in engagement.contacts
        if contact.contact_id == engagement.owner_contact_id
    )
    return (
        f"WHITE NIGHT ENGAGEMENT\n"
        f"Name: {engagement.name}\n"
        f"Engagement ID: {engagement.engagement_id}\n"
        f"Engagement Version: {engagement.version}\n"
        f"Engagement Fingerprint: {engagement.fingerprint}\n"
        f"Status: {engagement.status}\n"
        f"Owner: {owner.display_name} ({owner.role})\n"
        f"Contacts: {len(engagement.contacts)}\n"
        f"\n{render_rules_of_engagement(engagement.roe)}"
    )
