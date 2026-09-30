"""White Night Batch 4 deterministic policy compiler tests."""

from __future__ import annotations

from datetime import datetime, timezone
import copy
import ipaddress
import unittest

from nightrecon_shared_core.authorization import Scope, parse_target
from nightrecon_shared_core.engagement_policy import (
    EngagementExecutionPolicy,
    evaluate_action,
)
from nightrecon_white_engine.engagement_domain import (
    DataHandlingPolicy,
    EngagementContact,
    EngagementDefinition,
    RulesOfEngagement,
    ScopeDefinition,
)
from nightrecon_white_engine.policy_compiler import (
    CompiledPolicyBundle,
    PolicyCompilationError,
    compile_engagement_policy,
)


NOW = datetime(2026, 10, 2, 12, 0, tzinfo=timezone.utc)


def engagement(
    *,
    allowed=("192.0.2.0/24",),
    excluded=("192.0.2.250",),
    techniques=("discovery", "web.safe-active"),
    intrusiveness="safe-active",
    max_actions=100,
):
    roe = RulesOfEngagement(
        engagement_id="eng-policy-001",
        version=3,
        title="Policy compiler test",
        created_at="2026-09-29T12:00:00+00:00",
        valid_from="2026-10-01T08:00:00+00:00",
        valid_until="2026-10-05T18:00:00+00:00",
        scope=ScopeDefinition(
            allowed=tuple(allowed),
            excluded=tuple(excluded),
        ),
        allowed_techniques=tuple(techniques),
        prohibited_techniques=("destructive",),
        max_intrusiveness=intrusiveness,
        max_actions=max_actions,
        data_handling=DataHandlingPolicy(),
    )
    owner = EngagementContact(
        contact_id="owner",
        display_name="Owner",
        role="white-team-lead",
    )
    return EngagementDefinition(
        engagement_id="eng-policy-001",
        version=4,
        name="Compiler test engagement",
        created_at="2026-09-29T12:00:00+00:00",
        status="planned",
        owner_contact_id="owner",
        contacts=(owner,),
        roe=roe,
    )


class WhitePolicyCompilerTests(unittest.TestCase):
    def test_compiler_binds_source_versions_and_fingerprints(self) -> None:
        source = engagement()
        bundle = compile_engagement_policy(source)
        self.assertEqual(bundle.engagement_version, 4)
        self.assertEqual(bundle.roe_version, 3)
        self.assertEqual(bundle.engagement_fingerprint, source.fingerprint)
        self.assertEqual(bundle.roe_fingerprint, source.roe.fingerprint)
        self.assertEqual(len(bundle.policy_fingerprint), 64)
        self.assertEqual(len(bundle.bundle_fingerprint), 64)
        self.assertTrue(bundle.verify_integrity())

    def test_default_safe_active_maps_to_standard_impact_ceiling(self) -> None:
        bundle = compile_engagement_policy(engagement())
        self.assertEqual(bundle.policy.max_impact, "standard")

        allowed = evaluate_action(
            bundle.policy,
            engagement_status="active",
            capability="discovery",
            target="192.0.2.10",
            impact="standard",
            now=NOW,
        )
        self.assertTrue(allowed.allowed)

        denied = evaluate_action(
            bundle.policy,
            engagement_status="active",
            capability="discovery",
            target="192.0.2.10",
            impact="high",
            approval_present=True,
            now=NOW,
        )
        self.assertFalse(denied.allowed)
        self.assertEqual(denied.reason_code, "impact_exceeds_policy")

    def test_passive_and_intrusive_map_without_weakening(self) -> None:
        passive = compile_engagement_policy(
            engagement(intrusiveness="passive")
        ).policy
        self.assertEqual(passive.max_impact, "low")
        self.assertFalse(evaluate_action(
            passive,
            engagement_status="active",
            capability="discovery",
            target="192.0.2.10",
            impact="standard",
            now=NOW,
        ).allowed)

        intrusive = compile_engagement_policy(
            engagement(intrusiveness="intrusive")
        ).policy
        self.assertEqual(intrusive.max_impact, "high")
        needs_approval = evaluate_action(
            intrusive,
            engagement_status="active",
            capability="discovery",
            target="192.0.2.10",
            impact="high",
            now=NOW,
        )
        self.assertFalse(needs_approval.allowed)
        self.assertEqual(needs_approval.reason_code, "approval_required")
        self.assertTrue(evaluate_action(
            intrusive,
            engagement_status="active",
            capability="discovery",
            target="192.0.2.10",
            impact="high",
            approval_present=True,
            now=NOW,
        ).allowed)

    def test_destructive_intrusiveness_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            PolicyCompilationError, "destructive intrusiveness"
        ):
            compile_engagement_policy(
                engagement(intrusiveness="destructive")
            )

    def test_excluded_single_address_is_removed_from_cidr_exactly(self) -> None:
        bundle = compile_engagement_policy(engagement())
        scope = Scope.from_values(list(bundle.policy.scope))
        self.assertTrue(scope.is_authorized(parse_target("192.0.2.249")))
        self.assertFalse(scope.is_authorized(parse_target("192.0.2.250")))
        self.assertTrue(scope.is_authorized(parse_target("192.0.2.251")))
        # The original /24 target itself must not become authorized after a hole
        # has been carved from it.
        self.assertFalse(
            scope.is_authorized(parse_target("192.0.2.0/24"))
        )

    def test_ip_exclusion_projection_matches_effective_address_set(self) -> None:
        source = engagement(
            allowed=("192.0.2.0/24",),
            excluded=("192.0.2.1", "192.0.2.128/26"),
        )
        bundle = compile_engagement_policy(source)
        compiled = Scope.from_values(list(bundle.policy.scope))
        excluded_network = ipaddress.ip_network("192.0.2.128/26")
        for value in ipaddress.ip_network("192.0.2.0/24"):
            expected = (
                value != ipaddress.ip_address("192.0.2.1")
                and value not in excluded_network
            )
            self.assertEqual(
                compiled.is_authorized(parse_target(str(value))),
                expected,
                str(value),
            )

    def test_exact_ip_rule_stays_exact_ip(self) -> None:
        bundle = compile_engagement_policy(
            engagement(
                allowed=("192.0.2.10",),
                excluded=(),
                techniques=("discovery",),
            )
        )
        self.assertEqual(bundle.policy.scope, ("192.0.2.10",))
        compiled = Scope.from_values(list(bundle.policy.scope))
        self.assertTrue(compiled.is_authorized(parse_target("192.0.2.10")))
        self.assertFalse(
            compiled.is_authorized(parse_target("192.0.2.10/32"))
        )

    def test_hostname_exclusion_is_exact_and_case_normalized(self) -> None:
        bundle = compile_engagement_policy(
            engagement(
                allowed=("api.example.test", "APP.EXAMPLE.TEST"),
                excluded=("app.example.test",),
                techniques=("discovery",),
            )
        )
        self.assertEqual(bundle.policy.scope, ("api.example.test",))

    def test_exclusions_removing_everything_fail_closed(self) -> None:
        with self.assertRaisesRegex(
            PolicyCompilationError, "entire effective scope"
        ):
            compile_engagement_policy(
                engagement(
                    allowed=("192.0.2.0/24",),
                    excluded=("192.0.2.0/24",),
                    techniques=("discovery",),
                )
            )

    def test_invalid_shared_core_capability_fails_compilation(self) -> None:
        with self.assertRaisesRegex(
            PolicyCompilationError, "cannot be represented safely"
        ):
            compile_engagement_policy(
                engagement(
                    techniques=("technique with spaces",),
                )
            )

    def test_bundle_round_trip_and_tamper_detection(self) -> None:
        bundle = compile_engagement_policy(engagement())
        rebuilt = CompiledPolicyBundle.from_json(bundle.to_json())
        self.assertEqual(rebuilt, bundle)

        tampered = copy.deepcopy(bundle.to_dict())
        tampered["policy"]["max_actions"] += 1
        with self.assertRaisesRegex(
            PolicyCompilationError, "fingerprint verification failed"
        ):
            CompiledPolicyBundle.from_dict(tampered)

    def test_legacy_shared_policy_defaults_to_high_impact_ceiling(self) -> None:
        legacy = {
            "schema_version": 1,
            "engagement_id": "eng-legacy",
            "scope": ["192.0.2.0/24"],
            "valid_from": "2026-10-01T00:00:00+00:00",
            "valid_until": "2026-10-02T00:00:00+00:00",
            "max_actions": 10,
            "permitted_capabilities": ["discovery"],
            "approval_required_capabilities": [],
            "revoked": False,
            "actions_used": 0,
        }
        policy = EngagementExecutionPolicy.from_dict(legacy)
        self.assertEqual(policy.max_impact, "high")

    def test_capability_whitelist_is_not_broadened(self) -> None:
        bundle = compile_engagement_policy(
            engagement(techniques=("discovery", "web.safe-active"))
        )
        self.assertEqual(
            bundle.policy.permitted_capabilities,
            ("discovery", "web.safe-active"),
        )
        decision = evaluate_action(
            bundle.policy,
            engagement_status="active",
            capability="validation",
            target="192.0.2.10",
            impact="low",
            now=NOW,
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "capability_not_permitted")


if __name__ == "__main__":
    unittest.main()
