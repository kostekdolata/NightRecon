"""Tests for White Night immutable engagement, scope, and ROE authoring."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import unittest

from nightrecon_white_engine.engagement_domain import (
    ActionConstraints,
    AuthorizedContact,
    DataClassification,
    DataHandlingPolicy,
    EngagementDefinition,
    EngagementEnvironment,
    EngagementRole,
    EngagementWindow,
    ExportPolicy,
    IntrusivenessLevel,
    RulesOfEngagementTerms,
    ScopeDefinition,
    WindowKind,
    render_rules_of_engagement,
)


def make_definition(
    *,
    environment: EngagementEnvironment = EngagementEnvironment.PRODUCTION,
    constraints: ActionConstraints | None = None,
    scope: ScopeDefinition | None = None,
) -> EngagementDefinition:
    return EngagementDefinition(
        engagement_id="eng-2026-acme",
        revision=1,
        name="ACME September Assessment",
        purpose="Validate the explicitly authorized external and internal exposure surface.",
        created_at="2026-09-29T13:00:00+01:00",
        environment=environment,
        contacts=(
            AuthorizedContact(
                contact_id="security-lead",
                display_name="Security Lead",
                roles=(
                    EngagementRole.EMERGENCY_CONTACT,
                    EngagementRole.ENGAGEMENT_LEAD,
                ),
                organization="ACME Ltd",
                email="security@example.test",
            ),
            AuthorizedContact(
                contact_id="operator-1",
                display_name="Authorized Operator",
                roles=(EngagementRole.OPERATOR,),
            ),
        ),
        windows=(
            EngagementWindow(
                window_id="window-2",
                kind=WindowKind.EXERCISE,
                starts_at="2026-10-01T14:00:00+01:00",
                ends_at="2026-10-01T16:00:00+01:00",
                description="Tabletop and exercise-control window",
            ),
            EngagementWindow(
                window_id="window-1",
                kind=WindowKind.TESTING,
                starts_at="2026-10-01T09:00:00+01:00",
                ends_at="2026-10-01T12:00:00+01:00",
                description="Authorized technical testing window",
            ),
        ),
        scope=scope
        or ScopeDefinition(
            allowed_targets=(
                "Example.TEST",
                "192.0.2.0/24",
                "2001:db8::1",
            ),
            excluded_targets=("192.0.2.200",),
        ),
        constraints=constraints
        or ActionConstraints(
            allowed_action_classes=("validation", "discovery"),
            allowed_techniques=("T1595.002", "T1046"),
            max_intrusiveness=IntrusivenessLevel.SAFE_ACTIVE,
            max_actions=40,
            max_concurrent_actions=4,
        ),
        data_handling=DataHandlingPolicy(
            classification=DataClassification.CONFIDENTIAL,
            retention_days=30,
            export_policy=ExportPolicy.APPROVED_ONLY,
            require_encryption_at_rest=True,
            require_encryption_in_transit=True,
            notes="Evidence exports require engagement-lead review.",
        ),
        roe=RulesOfEngagementTerms(
            objective="Measure exposure without exceeding the approved action ceiling.",
            communications_channel="Approved engagement bridge and incident contact path.",
            emergency_procedure="Stop active work and contact the emergency contact.",
            prohibited_actions=(
                "No persistence outside an explicit cyber-range exercise.",
                "No destructive production actions.",
            ),
            additional_terms=(
                "Discovered assets outside scope are evidence only.",
                "Material scope changes require a new engagement revision.",
            ),
        ),
    )


class EngagementDomainTests(unittest.TestCase):
    def test_definition_normalizes_order_targets_and_times_deterministically(self) -> None:
        definition = make_definition()

        self.assertEqual(
            definition.scope.allowed_targets,
            ("192.0.2.0/24", "2001:db8::1", "example.test"),
        )
        self.assertEqual(definition.scope.excluded_targets, ("192.0.2.200",))
        self.assertEqual(
            definition.constraints.allowed_action_classes,
            ("discovery", "validation"),
        )
        self.assertEqual(
            definition.constraints.allowed_techniques,
            ("T1046", "T1595.002"),
        )
        self.assertEqual(
            [window.window_id for window in definition.windows],
            ["window-1", "window-2"],
        )
        self.assertEqual(definition.created_at, "2026-09-29T12:00:00Z")
        self.assertEqual(definition.windows[0].starts_at, "2026-10-01T08:00:00Z")

    def test_equivalent_ordering_produces_same_fingerprint(self) -> None:
        first = make_definition()
        second = replace(
            first,
            contacts=tuple(reversed(first.contacts)),
            windows=tuple(reversed(first.windows)),
            scope=ScopeDefinition(
                allowed_targets=("2001:0db8:0:0:0:0:0:1", "192.0.2.1/24", "example.test"),
                excluded_targets=("192.0.2.200",),
            ),
            constraints=ActionConstraints(
                allowed_action_classes=("validation", "discovery"),
                allowed_techniques=("T1595.002", "T1046"),
                max_intrusiveness=IntrusivenessLevel.SAFE_ACTIVE,
                max_actions=40,
                max_concurrent_actions=4,
            ),
        )
        self.assertEqual(first.to_json(), second.to_json())
        self.assertEqual(first.fingerprint(), second.fingerprint())

    def test_round_trip_preserves_definition_and_fingerprint(self) -> None:
        definition = make_definition()
        restored = EngagementDefinition.from_json(definition.to_json())
        self.assertEqual(restored, definition)
        self.assertEqual(restored.fingerprint(), definition.fingerprint())

    def test_models_are_immutable(self) -> None:
        definition = make_definition()
        with self.assertRaises(FrozenInstanceError):
            definition.name = "Changed"  # type: ignore[misc]

    def test_scope_allows_included_target_and_denies_explicit_exclusion(self) -> None:
        scope = ScopeDefinition(
            allowed_targets=("192.0.2.0/24", "example.test"),
            excluded_targets=("192.0.2.128/25",),
        )
        self.assertTrue(scope.allows("192.0.2.10"))
        self.assertFalse(scope.allows("192.0.2.200"))
        self.assertFalse(scope.allows("192.0.2.128/26"))
        self.assertTrue(scope.allows("example.test"))
        self.assertFalse(scope.allows("other.example.test"))

    def test_scope_rejects_exclusion_outside_allowed_scope(self) -> None:
        with self.assertRaisesRegex(ValueError, "contained by allowed scope"):
            ScopeDefinition(
                allowed_targets=("192.0.2.0/24",),
                excluded_targets=("198.51.100.10",),
            )

    def test_scope_rejects_semantic_duplicate_targets(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate"):
            ScopeDefinition(
                allowed_targets=("192.0.2.0/24", "192.0.2.1/24"),
            )

    def test_positive_action_budget_requires_bounded_concurrency_and_action_class(self) -> None:
        with self.assertRaisesRegex(ValueError, "allowed_action_classes"):
            ActionConstraints(max_actions=1, max_concurrent_actions=1)
        with self.assertRaisesRegex(ValueError, "must be positive"):
            ActionConstraints(
                allowed_action_classes=("discovery",),
                max_actions=1,
                max_concurrent_actions=0,
            )
        with self.assertRaisesRegex(ValueError, "cannot exceed"):
            ActionConstraints(
                allowed_action_classes=("discovery",),
                max_actions=1,
                max_concurrent_actions=2,
            )

    def test_zero_action_budget_is_valid_for_tabletop_only_engagement(self) -> None:
        constraints = ActionConstraints(
            max_intrusiveness=IntrusivenessLevel.PASSIVE,
            max_actions=0,
            max_concurrent_actions=0,
        )
        definition = make_definition(constraints=constraints)
        self.assertEqual(definition.constraints.max_actions, 0)

    def test_destructive_intrusiveness_is_cyber_range_only(self) -> None:
        destructive = ActionConstraints(
            allowed_action_classes=("simulation",),
            allowed_techniques=("T1485",),
            max_intrusiveness=IntrusivenessLevel.DESTRUCTIVE,
            max_actions=2,
            max_concurrent_actions=1,
        )
        with self.assertRaisesRegex(ValueError, "cyber-range"):
            make_definition(
                environment=EngagementEnvironment.PRODUCTION,
                constraints=destructive,
            )
        ranged = make_definition(
            environment=EngagementEnvironment.CYBER_RANGE,
            constraints=destructive,
        )
        self.assertEqual(
            ranged.constraints.max_intrusiveness,
            IntrusivenessLevel.DESTRUCTIVE,
        )

    def test_lead_and_emergency_contact_are_required(self) -> None:
        base = make_definition()
        no_emergency = (
            AuthorizedContact(
                contact_id="lead",
                display_name="Lead",
                roles=(EngagementRole.ENGAGEMENT_LEAD,),
            ),
        )
        with self.assertRaisesRegex(ValueError, "emergency contact"):
            replace(base, contacts=no_emergency)

        no_lead = (
            AuthorizedContact(
                contact_id="emergency",
                display_name="Emergency",
                roles=(EngagementRole.EMERGENCY_CONTACT,),
            ),
        )
        with self.assertRaisesRegex(ValueError, "engagement lead"):
            replace(base, contacts=no_lead)

    def test_windows_require_timezone_and_positive_duration(self) -> None:
        with self.assertRaisesRegex(ValueError, "timezone"):
            EngagementWindow(
                window_id="bad",
                kind=WindowKind.TESTING,
                starts_at="2026-10-01T09:00:00",
                ends_at="2026-10-01T10:00:00+00:00",
            )
        with self.assertRaisesRegex(ValueError, "later"):
            EngagementWindow(
                window_id="bad",
                kind=WindowKind.TESTING,
                starts_at="2026-10-01T10:00:00+00:00",
                ends_at="2026-10-01T09:00:00+00:00",
            )

    def test_data_handling_bounds_retention(self) -> None:
        with self.assertRaisesRegex(ValueError, "retention_days"):
            DataHandlingPolicy(retention_days=-1)
        with self.assertRaisesRegex(ValueError, "retention_days"):
            DataHandlingPolicy(retention_days=3651)

    def test_rendered_roe_contains_source_definition_and_authorization_boundary(self) -> None:
        definition = make_definition()
        rendered = render_rules_of_engagement(definition)

        self.assertIn("# Rules of Engagement — ACME September Assessment", rendered)
        self.assertIn(f"sha256:{definition.fingerprint()}", rendered)
        self.assertIn("\`192.0.2.200\`", rendered)
        self.assertIn("Maximum intrusiveness: **safe-active**", rendered)
        self.assertIn("Total action budget: **40**", rendered)
        self.assertIn("Retention: **30 days**", rendered)
        self.assertIn("does not by itself grant NightRecon execution authorization", rendered)

    def test_revision_changes_fingerprint(self) -> None:
        definition = make_definition()
        revision_two = replace(definition, revision=2)
        self.assertNotEqual(definition.fingerprint(), revision_two.fingerprint())

    def test_unknown_schema_fields_fail_closed(self) -> None:
        payload = make_definition().to_dict()
        payload["unexpected"] = True
        with self.assertRaisesRegex(ValueError, "schema is not supported"):
            EngagementDefinition.from_dict(payload)


if __name__ == "__main__":
    unittest.main()
