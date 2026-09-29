"""v0.43 Batch 1 controlled-validation technique registry tests."""

from __future__ import annotations

import unittest

from nightrecon_red_engine.validation_techniques import (
    BUILTIN_VALIDATION_TECHNIQUE_REGISTRY,
    ValidationTechniqueDefinition,
    ValidationTechniqueRegistry,
    build_validation_definition,
)


class ValidationTechniqueRegistryTests(unittest.TestCase):
    def test_builtin_registry_is_deterministic_and_metadata_only(self):
        first = BUILTIN_VALIDATION_TECHNIQUE_REGISTRY.list()
        second = BUILTIN_VALIDATION_TECHNIQUE_REGISTRY.list()

        self.assertEqual(first, second)
        self.assertEqual(
            tuple(item.technique_id for item in first),
            tuple(sorted(item.technique_id for item in first)),
        )
        self.assertEqual(len(first), 3)
        for item in first:
            self.assertEqual(item.adapter_kind, "read-only-proof")
            self.assertEqual(item.cleanup_mode, "none")
            self.assertNotIn("command", item.to_dict())
            self.assertNotIn("payload", item.to_dict())
            self.assertNotIn("script", item.to_dict())

    def test_definition_bridge_is_deterministic_but_does_not_execute(self):
        technique = BUILTIN_VALIDATION_TECHNIQUE_REGISTRY.get(
            "service.tls-property-proof"
        )
        first = build_validation_definition(
            technique,
            target="192.0.2.10",
        )
        second = build_validation_definition(
            technique,
            target="192.0.2.10",
        )
        other = build_validation_definition(
            technique,
            target="192.0.2.11",
        )

        self.assertEqual(first, second)
        self.assertNotEqual(first.validation_id, other.validation_id)
        self.assertEqual(first.target, "192.0.2.10")
        self.assertEqual(first.impact, "standard")
        self.assertFalse(first.requires_approval)

    def test_unknown_technique_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "unknown validation technique"):
            BUILTIN_VALIDATION_TECHNIQUE_REGISTRY.get("unknown.technique")

    def test_duplicate_technique_id_is_rejected(self):
        item = ValidationTechniqueDefinition(
            technique_id="service.read-only-proof",
            title="Proof",
            summary="Metadata-only proof.",
            target_kinds=("service",),
            evidence_keys=("state",),
        )
        with self.assertRaisesRegex(ValueError, "must be unique"):
            ValidationTechniqueRegistry((item, item))

    def test_secret_like_evidence_key_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "secret-like"):
            ValidationTechniqueDefinition(
                technique_id="service.bad-proof",
                title="Bad proof",
                summary="Rejected metadata.",
                target_kinds=("service",),
                evidence_keys=("api_token",),
            )

    def test_unknown_target_kind_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unsupported target kind"):
            ValidationTechniqueDefinition(
                technique_id="service.bad-target",
                title="Bad target",
                summary="Rejected metadata.",
                target_kinds=("shell",),
                evidence_keys=("state",),
            )

    def test_high_impact_requires_approval(self):
        with self.assertRaisesRegex(ValueError, "must require approval"):
            ValidationTechniqueDefinition(
                technique_id="service.high-proof",
                title="High proof",
                summary="High-impact metadata.",
                target_kinds=("service",),
                evidence_keys=("state",),
                impact="high",
                requires_approval=False,
            )

    def test_attack_mapping_format_is_strict_but_optional(self):
        item = ValidationTechniqueDefinition(
            technique_id="service.attack-mapped-proof",
            title="Mapped proof",
            summary="Mapping contract only.",
            target_kinds=("service",),
            evidence_keys=("state",),
            attack_ids=("T1046",),
        )
        self.assertEqual(item.attack_ids, ("T1046",))

        with self.assertRaisesRegex(ValueError, "invalid ATT&CK"):
            ValidationTechniqueDefinition(
                technique_id="service.bad-attack-id",
                title="Bad mapping",
                summary="Rejected mapping.",
                target_kinds=("service",),
                evidence_keys=("state",),
                attack_ids=("T-1046",),
            )


if __name__ == "__main__":
    unittest.main()
