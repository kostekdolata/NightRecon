"""Tests for passive NightRecon web form-intent metadata."""

import unittest

from nightrecon.web_crawl import (
    CrawlPage,
    WebFormInput,
    WebFormObservation,
)
from nightrecon.web_form_intent import (
    WorkflowFieldClass,
    classify_form_field,
    observe_form_intents,
)


class WebFormIntentTests(unittest.TestCase):
    def test_field_classification_is_metadata_only(self):
        fields = (
            WebFormInput(
                name="password",
                input_type="password",
            ),
            WebFormInput(
                name="csrf_token",
                input_type="hidden",
            ),
            WebFormInput(
                name="session_id",
                input_type="hidden",
            ),
            WebFormInput(
                name="redirect",
                input_type="hidden",
            ),
            WebFormInput(
                name="username",
                input_type="text",
            ),
        )

        classified = tuple(
            classify_form_field(field)
            for field in fields
        )

        self.assertEqual(
            tuple(
                item.field_class
                for item in classified
            ),
            (
                WorkflowFieldClass.CREDENTIAL,
                WorkflowFieldClass.ANTI_CSRF,
                WorkflowFieldClass.SESSION_TOKEN,
                WorkflowFieldClass.HIDDEN,
                WorkflowFieldClass.ORDINARY,
            ),
        )
        self.assertEqual(
            tuple(
                item.sensitive
                for item in classified
            ),
            (
                True,
                True,
                True,
                False,
                False,
            ),
        )
        self.assertTrue(
            all(
                item.value_retained is False
                for item in classified
            )
        )
        self.assertTrue(
            all(
                not hasattr(item, "value")
                for item in classified
            )
        )

    def test_password_type_is_credential_even_with_generic_name(self):
        field = classify_form_field(
            WebFormInput(
                name="field1",
                input_type="password",
            )
        )

        self.assertEqual(
            field.field_class,
            WorkflowFieldClass.CREDENTIAL,
        )
        self.assertTrue(field.sensitive)

    def test_same_origin_form_intent_is_observed_but_not_enabled(self):
        page = CrawlPage(
            url="https://example.test/login",
            status=200,
            content_type="text/html",
            byte_count=100,
            links=(),
            forms=(
                WebFormObservation(
                    action="https://example.test/session",
                    method="post",
                    inputs=(
                        WebFormInput(
                            name="username",
                            input_type="text",
                        ),
                        WebFormInput(
                            name="password",
                            input_type="password",
                        ),
                        WebFormInput(
                            name="csrf_token",
                            input_type="hidden",
                        ),
                    ),
                ),
            ),
        )

        intents = observe_form_intents(
            pages=(page,),
            origin="https://example.test",
        )

        self.assertEqual(len(intents), 1)
        intent = intents[0]
        self.assertEqual(
            intent.source_url,
            "https://example.test/login",
        )
        self.assertEqual(
            intent.action_url,
            "https://example.test/session",
        )
        self.assertEqual(
            intent.method,
            "POST",
        )
        self.assertTrue(
            intent.action_same_origin
        )
        self.assertFalse(
            intent.submission_enabled
        )
        self.assertTrue(
            all(
                field.value_retained is False
                for field in intent.fields
            )
        )

    def test_cross_origin_form_action_is_observed_as_not_same_origin(self):
        page = CrawlPage(
            url="https://example.test/",
            status=200,
            content_type="text/html",
            byte_count=100,
            links=(),
            forms=(
                WebFormObservation(
                    action="https://other.test/submit",
                    method="POST",
                    inputs=(),
                ),
            ),
        )

        intents = observe_form_intents(
            pages=(page,),
            origin="https://example.test",
        )

        self.assertEqual(len(intents), 1)
        self.assertFalse(
            intents[0].action_same_origin
        )
        self.assertFalse(
            intents[0].submission_enabled
        )

    def test_outside_origin_pages_and_failed_pages_are_not_modelled(self):
        pages = (
            CrawlPage(
                url="https://outside.test/",
                status=200,
                content_type="text/html",
                byte_count=100,
                links=(),
                forms=(
                    WebFormObservation(
                        action="https://outside.test/submit",
                        method="POST",
                        inputs=(),
                    ),
                ),
            ),
            CrawlPage(
                url="https://example.test/error",
                status=None,
                content_type="",
                byte_count=0,
                links=(),
                error="TimeoutError: timed out",
                forms=(
                    WebFormObservation(
                        action="https://example.test/submit",
                        method="POST",
                        inputs=(),
                    ),
                ),
            ),
        )

        self.assertEqual(
            observe_form_intents(
                pages=pages,
                origin="https://example.test",
            ),
            (),
        )

    def test_invalid_action_remains_non_executable_metadata(self):
        page = CrawlPage(
            url="https://example.test/",
            status=200,
            content_type="text/html",
            byte_count=100,
            links=(),
            forms=(
                WebFormObservation(
                    action="javascript:submitForm()",
                    method="POST",
                    inputs=(
                        WebFormInput(
                            name="auth_token",
                            input_type="hidden",
                        ),
                    ),
                ),
            ),
        )

        intents = observe_form_intents(
            pages=(page,),
            origin="https://example.test",
        )

        self.assertEqual(len(intents), 1)
        self.assertEqual(
            intents[0].action_url,
            "",
        )
        self.assertFalse(
            intents[0].action_same_origin
        )
        self.assertFalse(
            intents[0].submission_enabled
        )
        self.assertEqual(
            intents[0].fields[0].field_class,
            WorkflowFieldClass.SESSION_TOKEN,
        )


if __name__ == "__main__":
    unittest.main()
