"""Tests for NightRecon declarative assessment check packs."""

import json
import unittest

from nightrecon.assessment_engine import AssessmentContext
from nightrecon.check_packs import (
    CheckPack,
    DeclarativeAssessmentCheck,
    load_check_pack_json,
)
from nightrecon.service_detection import ServiceDetectionResult
from nightrecon.software_identity import SoftwareIdentity


class CheckPackTests(unittest.TestCase):
    def test_pack_loads_declarative_check_and_emits_evidence(self):
        payload = {
            "schema_version": 1,
            "pack_id": "nightrecon.test.web",
            "name": "Test Web Pack",
            "version": "1.0.0",
            "checks": [
                {
                    "check_id": "web.server.nginx",
                    "name": "Nginx Server Observed",
                    "family": "web",
                    "description": "Detect explicit nginx server metadata.",
                    "intrusiveness": "passive",
                    "supported_services": ["http", "https"],
                    "tags": ["web", "inventory"],
                    "conditions": [
                        {
                            "field": "software.product",
                            "operator": "equals",
                            "value": "nginx",
                        }
                    ],
                    "finding": {
                        "title": "Nginx server observed",
                        "summary": "The HTTP service identified itself as nginx.",
                        "severity": "informational",
                        "remediation": "",
                        "references": [],
                    },
                    "evidence_fields": [
                        "software.product",
                        "software.version",
                    ],
                }
            ],
        }

        pack = load_check_pack_json(
            json.dumps(payload)
        )

        self.assertEqual(
            pack,
            CheckPack(
                schema_version=1,
                pack_id="nightrecon.test.web",
                name="Test Web Pack",
                version="1.0.0",
                checks=pack.checks,
            ),
        )
        self.assertEqual(len(pack.checks), 1)
        self.assertIsInstance(
            pack.checks[0],
            DeclarativeAssessmentCheck,
        )

        service = ServiceDetectionResult(
            address="127.0.0.1",
            port=80,
            service="http",
            banner="",
            software_identity=SoftwareIdentity(
                product="nginx",
                version="1.24.0",
                source="http-server",
                evidence="nginx/1.24.0",
            ),
        )
        context = AssessmentContext(
            target="127.0.0.1",
            address="127.0.0.1",
            port=80,
            service="http",
            authorized=True,
            service_result=service,
        )

        findings = pack.checks[0].run(context)

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0].check_id,
            "web.server.nginx",
        )
        self.assertEqual(
            findings[0].evidence,
            (
                "software.product=nginx",
                "software.version=1.24.0",
            ),
        )

    def test_all_conditions_must_match(self):
        payload = {
            "schema_version": 1,
            "pack_id": "nightrecon.test.tls",
            "name": "Test TLS Pack",
            "version": "1.0.0",
            "checks": [
                {
                    "check_id": "tls.example",
                    "name": "TLS Example",
                    "family": "tls",
                    "description": "Example TLS condition.",
                    "intrusiveness": "passive",
                    "supported_services": ["https"],
                    "conditions": [
                        {
                            "field": "tls_version",
                            "operator": "equals",
                            "value": "TLSv1.3",
                        },
                        {
                            "field": "http_server",
                            "operator": "contains",
                            "value": "nginx",
                        },
                    ],
                    "finding": {
                        "title": "Matched",
                        "summary": "All conditions matched.",
                    },
                }
            ],
        }

        pack = load_check_pack_json(
            json.dumps(payload)
        )
        service = ServiceDetectionResult(
            address="127.0.0.1",
            port=443,
            service="https",
            banner="",
            tls_version="TLSv1.3",
            http_server="Apache/2.4.58",
        )
        context = AssessmentContext(
            target="example.test",
            address="127.0.0.1",
            port=443,
            service="https",
            authorized=True,
            service_result=service,
        )

        self.assertEqual(
            pack.checks[0].run(context),
            (),
        )

    def test_unknown_field_is_rejected(self):
        payload = {
            "schema_version": 1,
            "pack_id": "nightrecon.test.invalid",
            "name": "Invalid Pack",
            "version": "1.0.0",
            "checks": [
                {
                    "check_id": "invalid.field",
                    "name": "Invalid",
                    "family": "test",
                    "description": "Invalid field.",
                    "intrusiveness": "passive",
                    "conditions": [
                        {
                            "field": "__class__",
                            "operator": "present",
                        }
                    ],
                    "finding": {
                        "title": "Invalid",
                        "summary": "Invalid.",
                    },
                }
            ],
        }

        with self.assertRaisesRegex(
            ValueError,
            "Unsupported declarative field",
        ):
            load_check_pack_json(
                json.dumps(payload)
            )

    def test_unknown_operator_is_rejected(self):
        payload = {
            "schema_version": 1,
            "pack_id": "nightrecon.test.invalid",
            "name": "Invalid Pack",
            "version": "1.0.0",
            "checks": [
                {
                    "check_id": "invalid.operator",
                    "name": "Invalid",
                    "family": "test",
                    "description": "Invalid operator.",
                    "intrusiveness": "passive",
                    "conditions": [
                        {
                            "field": "service",
                            "operator": "eval",
                            "value": "anything",
                        }
                    ],
                    "finding": {
                        "title": "Invalid",
                        "summary": "Invalid.",
                    },
                }
            ],
        }

        with self.assertRaisesRegex(
            ValueError,
            "Unsupported declarative operator",
        ):
            load_check_pack_json(
                json.dumps(payload)
            )

    def test_unsupported_schema_version_is_rejected(self):
        payload = {
            "schema_version": 99,
            "pack_id": "nightrecon.test.future",
            "name": "Future Pack",
            "version": "1.0.0",
            "checks": [],
        }

        with self.assertRaisesRegex(
            ValueError,
            "Unsupported check-pack schema version",
        ):
            load_check_pack_json(
                json.dumps(payload)
            )


if __name__ == "__main__":
    unittest.main()
