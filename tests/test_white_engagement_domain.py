"""White Night Batch 3 engagement/scope/ROE domain tests."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
import json
import unittest

from nightrecon_white_engine.engagement_domain import (
    DataHandlingPolicy,
    EngagementContact,
    EngagementDefinition,
    RulesOfEngagement,
    ScopeDefinition,
)
from nightrecon_white_engine.roe_render import (
    render_engagement_summary,
    render_rules_of_engagement,
)


def sample_roe(**overrides):
    values = dict(
        engagement_id="eng-acme-001",
        version=1,
        title="ACME Authorized Security Assessment",
        created_at="2026-09-29T12:00:00+00:00",
        valid_from="2026-10-01T08:00:00+00:00",
        valid_until="2026-10-05T18:00:00+00:00",
        scope=ScopeDefinition(
            allowed=("192.0.2.0/24", "app.example.test"),
            excluded=("192.0.2.250",),
        ),
        allowed_techniques=("discovery", "web.safe-active"),
        prohibited_techniques=("destructive",),
        max_intrusiveness="safe-active",
        max_actions=250,
        data_handling=DataHandlingPolicy(
            classification="confidential",
            retention_days=120,
            export_allowed=True,
            notes="Customer-approved encrypted evidence handling.",
        ),
        deviation_requires_approval=True,
        notes="Stop on customer request.",
    )
    values.update(overrides)
    return RulesOfEngagement(**values)


def sample_engagement(**overrides):
    contacts = (
        EngagementContact(
            contact_id="operator-1",
            display_name="Lead Operator",
            role="white-team-lead",
            email="lead@example.test",
        ),
        EngagementContact(
            contact_id="customer-1",
            display_name="Customer Authority",
            role="authorizing-official",
            email="authority@example.test",
        ),
    )
    values = dict(
        engagement_id="eng-acme-001",
        version=1,
        name="ACME October Assessment",
        created_at="2026-09-29T12:00:00+00:00",
        status="planned",
        owner_contact_id="operator-1",
        contacts=contacts,
        roe=sample_roe(),
        description="Authorized test engagement.",
    )
    values.update(overrides)
    return EngagementDefinition(**values)


class WhiteEngagementDomainTests(unittest.TestCase):
    def test_domain_models_are_immutable(self) -> None:
        engagement = sample_engagement()
        with self.assertRaises(FrozenInstanceError):
            engagement.status = "active"  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            engagement.roe.max_actions = 999  # type: ignore[misc]

    def test_round_trip_is_deterministic(self) -> None:
        engagement = sample_engagement()
        payload = engagement.to_dict()
        rebuilt = EngagementDefinition.from_dict(
            json.loads(json.dumps(payload))
        )
        self.assertEqual(rebuilt, engagement)
        self.assertEqual(rebuilt.canonical_json(), engagement.canonical_json())
        self.assertEqual(rebuilt.fingerprint, engagement.fingerprint)

    def test_semantically_equivalent_unordered_sets_normalize_identically(self) -> None:
        first = sample_engagement()
        reordered_contacts = tuple(reversed(first.contacts))
        second = sample_engagement(
            contacts=reordered_contacts,
            roe=sample_roe(
                scope=ScopeDefinition(
                    allowed=("app.example.test", "192.0.2.0/24"),
                    excluded=("192.0.2.250",),
                ),
                allowed_techniques=("web.safe-active", "discovery"),
            ),
        )
        self.assertEqual(first.fingerprint, second.fingerprint)
        self.assertEqual(first.roe.fingerprint, second.roe.fingerprint)

    def test_fingerprint_changes_when_authoring_intent_changes(self) -> None:
        first = sample_engagement()
        second = sample_engagement(
            version=2,
            roe=sample_roe(version=2, max_actions=251),
        )
        self.assertNotEqual(first.fingerprint, second.fingerprint)
        self.assertNotEqual(first.roe.fingerprint, second.roe.fingerprint)

    def test_scope_requires_at_least_one_allowed_rule(self) -> None:
        with self.assertRaisesRegex(ValueError, "at least 1"):
            ScopeDefinition(allowed=())

    def test_scope_reuses_shared_core_target_rule_validation(self) -> None:
        with self.assertRaises(ValueError):
            ScopeDefinition(allowed=("not a valid target rule !",))

    def test_duplicate_scope_rules_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicates"):
            ScopeDefinition(allowed=("192.0.2.1", "192.0.2.1"))

    def test_time_window_must_be_timezone_aware_and_ordered(self) -> None:
        with self.assertRaisesRegex(ValueError, "timezone"):
            sample_roe(valid_from="2026-10-01T08:00:00")
        with self.assertRaisesRegex(ValueError, "later"):
            sample_roe(
                valid_from="2026-10-05T18:00:00+00:00",
                valid_until="2026-10-01T08:00:00+00:00",
            )

    def test_allowed_and_prohibited_techniques_cannot_overlap(self) -> None:
        with self.assertRaisesRegex(ValueError, "both allowed and prohibited"):
            sample_roe(
                allowed_techniques=("discovery",),
                prohibited_techniques=("discovery",),
            )

    def test_intrusiveness_is_explicitly_bounded_to_known_levels(self) -> None:
        with self.assertRaisesRegex(ValueError, "max_intrusiveness"):
            sample_roe(max_intrusiveness="unlimited")

    def test_action_budget_must_be_positive(self) -> None:
        with self.assertRaisesRegex(ValueError, "positive integer"):
            sample_roe(max_actions=0)

    def test_retention_policy_is_bounded(self) -> None:
        with self.assertRaisesRegex(ValueError, "between 1 and 3650"):
            DataHandlingPolicy(retention_days=0)
        with self.assertRaisesRegex(ValueError, "between 1 and 3650"):
            DataHandlingPolicy(retention_days=3651)

    def test_owner_must_be_present_in_contacts(self) -> None:
        with self.assertRaisesRegex(ValueError, "owner_contact_id"):
            sample_engagement(owner_contact_id="missing")

    def test_contacts_must_have_unique_ids(self) -> None:
        contact = EngagementContact(
            contact_id="same",
            display_name="One",
            role="operator",
        )
        with self.assertRaisesRegex(ValueError, "unique"):
            sample_engagement(
                owner_contact_id="same",
                contacts=(contact, contact),
            )

    def test_roe_must_belong_to_same_engagement(self) -> None:
        with self.assertRaisesRegex(ValueError, "belong"):
            sample_engagement(
                roe=sample_roe(engagement_id="eng-other-001")
            )

    def test_unknown_schema_fields_fail_closed(self) -> None:
        payload = sample_roe().to_dict()
        payload["unexpected"] = True
        with self.assertRaisesRegex(ValueError, "schema"):
            RulesOfEngagement.from_dict(payload)

    def test_rendered_roe_contains_fingerprint_and_non_authorization_notice(self) -> None:
        rendered = render_rules_of_engagement(sample_roe())
        self.assertIn("ROE Fingerprint:", rendered)
        self.assertIn("ALLOWED SCOPE", rendered)
        self.assertIn("EXCLUSIONS", rendered)
        self.assertIn("shared-core policy enforcement remains authoritative", rendered)

    def test_engagement_summary_contains_owner_and_roe(self) -> None:
        rendered = render_engagement_summary(sample_engagement())
        self.assertIn("Lead Operator (white-team-lead)", rendered)
        self.assertIn("ACME Authorized Security Assessment", rendered)
        self.assertIn("Engagement Fingerprint:", rendered)

    def test_domain_has_no_authorization_method(self) -> None:
        roe = sample_roe()
        engagement = sample_engagement()
        for name in ("authorize", "execute", "scan", "approve"):
            self.assertFalse(hasattr(roe, name))
            self.assertFalse(hasattr(engagement, name))


if __name__ == "__main__":
    unittest.main()
