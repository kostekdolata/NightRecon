"""Red Checks ecosystem applies local trust/capability policy to verified packs."""

from __future__ import annotations

import unittest

from nightrecon_red_engine.assessment_engine import CheckIntrusiveness
from nightrecon_red_engine.check_ecosystem import (
    CheckEcosystemPolicy,
    EcosystemPackProvenance,
    VerifiedEcosystemPack,
    build_check_catalog,
    evaluate_pack_eligibility,
)
from nightrecon_red_engine.check_packs import load_check_pack_payload


def pack(*, intrusive=False, capability=""):
    check = {
        "check_id": "test.check",
        "name": "Test check",
        "family": "tls",
        "description": "Declarative fixture",
        "intrusiveness": "intrusive" if intrusive else "safe-active",
        "supported_services": ["https"],
        "tags": ["configuration"],
        "conditions": [{"field": "tls_version", "operator": "present"}],
        "finding": {"title": "Finding", "summary": "Summary"},
        "evidence_fields": ["tls_version"],
    }
    if capability:
        check["required_capabilities"] = [capability]
    return load_check_pack_payload({
        "schema_version": 1,
        "pack_id": "community.tls",
        "name": "Community TLS",
        "version": "1.0.0",
        "checks": [check],
    })


def artifact(item, signer="trusted-key"):
    return VerifiedEcosystemPack(
        item,
        EcosystemPackProvenance(
            signer_key_id=signer,
            source_feed_id="official-feed",
            sha256="a" * 64,
        ),
    )


class CheckEcosystemTests(unittest.TestCase):
    def test_eligible_pack_is_cataloged_with_provenance_and_search_metadata(self):
        policy = CheckEcosystemPolicy(
            trusted_signers=("trusted-key",),
            max_intrusiveness=CheckIntrusiveness.SAFE_ACTIVE,
        )
        catalog = build_check_catalog((artifact(pack()),), policy)
        entry = catalog.entries[0]
        self.assertTrue(entry.eligible)
        self.assertEqual(entry.signer_key_id, "trusted-key")
        self.assertEqual(entry.families, ("tls",))
        self.assertEqual(entry.tags, ("configuration",))
        self.assertEqual(catalog.search(service="https"), (entry,))
        self.assertEqual(catalog.search(eligible_only=True), (entry,))

    def test_untrusted_signer_is_ineligible(self):
        result = evaluate_pack_eligibility(
            artifact(pack(), signer="unknown"),
            CheckEcosystemPolicy(trusted_signers=("trusted-key",)),
        )
        self.assertFalse(result.eligible)
        self.assertIn("untrusted_signer", result.reason_codes)

    def test_intrusive_pack_requires_explicit_ecosystem_policy(self):
        result = evaluate_pack_eligibility(
            artifact(pack(intrusive=True)),
            CheckEcosystemPolicy(
                trusted_signers=("trusted-key",),
                max_intrusiveness=CheckIntrusiveness.SAFE_ACTIVE,
            ),
        )
        self.assertFalse(result.eligible)
        self.assertTrue(any(
            item.startswith("intrusiveness_exceeded:")
            for item in result.reason_codes
        ))

    def test_required_capability_must_be_allowlisted(self):
        result = evaluate_pack_eligibility(
            artifact(pack(capability="browser")),
            CheckEcosystemPolicy(
                trusted_signers=("trusted-key",),
                allowed_capabilities=(),
            ),
        )
        self.assertFalse(result.eligible)
        self.assertTrue(any(
            "capability_not_allowed" in item for item in result.reason_codes
        ))

    def test_duplicate_pack_version_is_rejected(self):
        item = artifact(pack())
        with self.assertRaisesRegex(ValueError, "duplicate"):
            build_check_catalog(
                (item, item),
                CheckEcosystemPolicy(trusted_signers=("trusted-key",)),
            )


if __name__ == "__main__":
    unittest.main()
