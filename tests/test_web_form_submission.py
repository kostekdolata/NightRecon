"""Tests for NightRecon explicit form-submission policy."""

import unittest

from nightrecon.web_form_intent import (
    WorkflowFieldClass,
    WorkflowFormFieldIntent,
    WorkflowFormIntent,
)
from nightrecon.web_form_submission import (
    FormSubmissionPolicy,
    authorize_form_submission,
)


def _intent(
    *,
    action_url="https://example.test/session",
    method="POST",
    same_origin=True,
):
    return WorkflowFormIntent(
        source_url="https://example.test/login",
        action_url=action_url,
        method=method,
        action_same_origin=same_origin,
        fields=(
            WorkflowFormFieldIntent(
                name="username",
                input_type="text",
                field_class=WorkflowFieldClass.ORDINARY,
                sensitive=False,
            ),
            WorkflowFormFieldIntent(
                name="csrf_token",
                input_type="hidden",
                field_class=WorkflowFieldClass.ANTI_CSRF,
                sensitive=True,
            ),
            WorkflowFormFieldIntent(
                name="password",
                input_type="password",
                field_class=WorkflowFieldClass.CREDENTIAL,
                sensitive=True,
            ),
        ),
        submission_enabled=False,
    )


class FormSubmissionPolicyTests(unittest.TestCase):
    def test_submission_is_disabled_by_default(self):
        policy = FormSubmissionPolicy(
            origin="https://example.test",
            allowed_fields=("username",),
        )

        decision = authorize_form_submission(
            intent=_intent(),
            policy=policy,
            provided_field_names=("username",),
            submissions_used=0,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "form_submission_not_enabled",
        )

    def test_same_origin_allowlisted_ordinary_field_can_be_authorized(self):
        policy = FormSubmissionPolicy(
            origin="https://example.test",
            enabled=True,
            allowed_fields=("username",),
        )

        decision = authorize_form_submission(
            intent=_intent(),
            policy=policy,
            provided_field_names=("username",),
            submissions_used=0,
        )

        self.assertTrue(decision.allowed)
        self.assertEqual(
            decision.reason,
            "authorized",
        )
        self.assertEqual(
            decision.approved_fields,
            ("username",),
        )
        self.assertFalse(
            hasattr(decision, "values")
        )

    def test_cross_origin_form_is_rejected(self):
        policy = FormSubmissionPolicy(
            origin="https://example.test",
            enabled=True,
            allowed_fields=("username",),
        )

        decision = authorize_form_submission(
            intent=_intent(
                action_url="https://other.test/submit",
                same_origin=False,
            ),
            policy=policy,
            provided_field_names=("username",),
            submissions_used=0,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "form_action_not_same_origin",
        )

    def test_submission_budget_is_enforced(self):
        policy = FormSubmissionPolicy(
            origin="https://example.test",
            enabled=True,
            max_submissions=1,
            allowed_fields=("username",),
        )

        decision = authorize_form_submission(
            intent=_intent(),
            policy=policy,
            provided_field_names=("username",),
            submissions_used=1,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "form_submission_budget_exhausted",
        )

    def test_non_allowlisted_field_is_rejected(self):
        policy = FormSubmissionPolicy(
            origin="https://example.test",
            enabled=True,
            allowed_fields=("username",),
        )

        decision = authorize_form_submission(
            intent=_intent(),
            policy=policy,
            provided_field_names=("password",),
            submissions_used=0,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "form_field_not_allowlisted",
        )

    def test_unknown_field_is_rejected(self):
        policy = FormSubmissionPolicy(
            origin="https://example.test",
            enabled=True,
            allowed_fields=("username", "made_up"),
        )

        decision = authorize_form_submission(
            intent=_intent(),
            policy=policy,
            provided_field_names=("made_up",),
            submissions_used=0,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "unknown_form_field",
        )

    def test_sensitive_field_requires_explicit_class_permission(self):
        policy = FormSubmissionPolicy(
            origin="https://example.test",
            enabled=True,
            allowed_fields=("csrf_token",),
        )

        blocked = authorize_form_submission(
            intent=_intent(),
            policy=policy,
            provided_field_names=("csrf_token",),
            submissions_used=0,
        )

        self.assertFalse(blocked.allowed)
        self.assertEqual(
            blocked.reason,
            "sensitive_form_field_not_allowed",
        )

        permitted_policy = FormSubmissionPolicy(
            origin="https://example.test",
            enabled=True,
            allowed_fields=("csrf_token",),
            allowed_sensitive_classes=(
                WorkflowFieldClass.ANTI_CSRF,
            ),
        )

        permitted = authorize_form_submission(
            intent=_intent(),
            policy=permitted_policy,
            provided_field_names=("csrf_token",),
            submissions_used=0,
        )

        self.assertTrue(permitted.allowed)

    def test_credential_field_remains_blocked_when_only_csrf_is_permitted(self):
        policy = FormSubmissionPolicy(
            origin="https://example.test",
            enabled=True,
            allowed_fields=("password",),
            allowed_sensitive_classes=(
                WorkflowFieldClass.ANTI_CSRF,
            ),
        )

        decision = authorize_form_submission(
            intent=_intent(),
            policy=policy,
            provided_field_names=("password",),
            submissions_used=0,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "sensitive_form_field_not_allowed",
        )

    def test_destructive_looking_action_is_blocked_by_default(self):
        policy = FormSubmissionPolicy(
            origin="https://example.test",
            enabled=True,
            allowed_fields=("username",),
        )

        decision = authorize_form_submission(
            intent=_intent(
                action_url="https://example.test/account/delete",
            ),
            policy=policy,
            provided_field_names=("username",),
            submissions_used=0,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "destructive_form_action_blocked",
        )

    def test_non_post_method_is_blocked_by_default(self):
        policy = FormSubmissionPolicy(
            origin="https://example.test",
            enabled=True,
            allowed_fields=("username",),
        )

        decision = authorize_form_submission(
            intent=_intent(method="PUT"),
            policy=policy,
            provided_field_names=("username",),
            submissions_used=0,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "form_method_not_allowed",
        )

    def test_no_fields_is_rejected(self):
        policy = FormSubmissionPolicy(
            origin="https://example.test",
            enabled=True,
            allowed_fields=("username",),
        )

        decision = authorize_form_submission(
            intent=_intent(),
            policy=policy,
            provided_field_names=(),
            submissions_used=0,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "no_form_fields_approved",
        )

    def test_invalid_policy_limits_fail_closed(self):
        with self.assertRaises(ValueError):
            FormSubmissionPolicy(
                origin="https://example.test",
                max_submissions=0,
            )

        with self.assertRaises(ValueError):
            FormSubmissionPolicy(
                origin="https://example.test",
                allowed_methods=(),
            )


if __name__ == "__main__":
    unittest.main()
