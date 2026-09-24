"""Tests for the NightRecon assessment engine."""

import unittest

from nightrecon.assessment_engine import (
    AssessmentCheckMetadata,
    AssessmentContext,
    AssessmentEngine,
    AssessmentFinding,
    CheckIntrusiveness,
    CheckRegistry,
)


class _Check:
    def __init__(
        self,
        *,
        check_id,
        family="test",
        intrusiveness=CheckIntrusiveness.SAFE_ACTIVE,
        supported_services=(),
        tags=(),
        findings=(),
        error=None,
    ):
        self.metadata = AssessmentCheckMetadata(
            check_id=check_id,
            name=check_id,
            family=family,
            description="Test check.",
            intrusiveness=intrusiveness,
            supported_services=supported_services,
            tags=tags,
        )
        self._findings = findings
        self._error = error
        self.calls = []

    def run(self, context):
        self.calls.append(context)

        if self._error is not None:
            raise self._error

        return self._findings


class AssessmentEngineTests(unittest.TestCase):
    def test_registry_rejects_duplicate_check_ids(self):
        registry = CheckRegistry()
        registry.register(_Check(check_id="test.one"))

        with self.assertRaises(ValueError):
            registry.register(_Check(check_id="test.one"))

    def test_registry_selection_is_deterministic(self):
        registry = CheckRegistry()
        registry.register(
            _Check(
                check_id="web.headers",
                family="web",
                tags=("http", "headers"),
            )
        )
        registry.register(
            _Check(
                check_id="tls.certificate",
                family="tls",
                tags=("tls", "certificate"),
            )
        )
        registry.register(
            _Check(
                check_id="web.server",
                family="web",
                tags=("http", "fingerprint"),
            )
        )

        selected = registry.select(
            families=("web",),
        )

        self.assertEqual(
            tuple(
                check.metadata.check_id
                for check in selected
            ),
            (
                "web.headers",
                "web.server",
            ),
        )

    def test_default_policy_runs_safe_active_check(self):
        finding = AssessmentFinding(
            check_id="web.safe",
            title="Example finding",
            summary="Example summary.",
            evidence=("header=x",),
        )
        check = _Check(
            check_id="web.safe",
            findings=(finding,),
        )
        engine = AssessmentEngine()

        results = engine.run(
            checks=(check,),
            context=AssessmentContext(
                target="example.test",
                address="127.0.0.1",
                port=80,
                service="http",
                authorized=True,
            ),
        )

        self.assertEqual(results[0].status, "completed")
        self.assertEqual(results[0].findings, (finding,))
        self.assertEqual(len(check.calls), 1)

    def test_default_policy_blocks_intrusive_check(self):
        check = _Check(
            check_id="web.intrusive",
            intrusiveness=CheckIntrusiveness.INTRUSIVE,
        )
        engine = AssessmentEngine()

        results = engine.run(
            checks=(check,),
            context=AssessmentContext(
                target="example.test",
                address="127.0.0.1",
                port=80,
                service="http",
                authorized=True,
            ),
        )

        self.assertEqual(results[0].status, "skipped")
        self.assertEqual(
            results[0].reason,
            "intrusiveness_not_allowed",
        )
        self.assertEqual(check.calls, [])

    def test_unauthorized_context_is_rejected_before_checks_run(self):
        check = _Check(check_id="test.safe")
        engine = AssessmentEngine()

        with self.assertRaises(PermissionError):
            engine.run(
                checks=(check,),
                context=AssessmentContext(
                    target="example.test",
                    address="127.0.0.1",
                    port=80,
                    service="http",
                    authorized=False,
                ),
            )

        self.assertEqual(check.calls, [])

    def test_service_restriction_skips_nonmatching_check(self):
        check = _Check(
            check_id="tls.only",
            supported_services=("https",),
        )
        engine = AssessmentEngine()

        results = engine.run(
            checks=(check,),
            context=AssessmentContext(
                target="example.test",
                address="127.0.0.1",
                port=80,
                service="http",
                authorized=True,
            ),
        )

        self.assertEqual(results[0].status, "skipped")
        self.assertEqual(
            results[0].reason,
            "service_not_supported",
        )
        self.assertEqual(check.calls, [])

    def test_check_errors_are_fail_soft(self):
        check = _Check(
            check_id="test.error",
            error=OSError("check failed"),
        )
        engine = AssessmentEngine()

        results = engine.run(
            checks=(check,),
            context=AssessmentContext(
                target="example.test",
                address="127.0.0.1",
                port=80,
                service="http",
                authorized=True,
            ),
        )

        self.assertEqual(results[0].status, "error")
        self.assertEqual(results[0].error, "check failed")

    def test_explicit_intrusiveness_ceiling_can_enable_intrusive_check(self):
        check = _Check(
            check_id="test.intrusive",
            intrusiveness=CheckIntrusiveness.INTRUSIVE,
        )
        engine = AssessmentEngine(
            max_intrusiveness=CheckIntrusiveness.INTRUSIVE,
        )

        results = engine.run(
            checks=(check,),
            context=AssessmentContext(
                target="example.test",
                address="127.0.0.1",
                port=80,
                service="http",
                authorized=True,
            ),
        )

        self.assertEqual(results[0].status, "completed")
        self.assertEqual(len(check.calls), 1)


if __name__ == "__main__":
    unittest.main()
