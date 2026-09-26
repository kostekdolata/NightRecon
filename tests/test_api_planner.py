"""Tests for NightRecon safe API operation planning."""

import unittest

from nightrecon.api_models import (
    ApiInventory,
    ApiOperation,
    ApiParameter,
)
from nightrecon.api_planner import (
    operation_selector,
    select_api_operations,
)


def _inventory():
    return ApiInventory(
        specification="openapi",
        specification_version="3.1.0",
        title="API",
        api_version="1",
        servers=(),
        operations=(
            ApiOperation(
                method="GET",
                path="/status",
                operation_id="status",
                summary="",
                parameters=(),
                request_content_types=(),
                response_statuses=("200",),
                security_schemes=(),
            ),
            ApiOperation(
                method="HEAD",
                path="/health",
                operation_id="",
                summary="",
                parameters=(),
                request_content_types=(),
                response_statuses=("200",),
                security_schemes=(),
            ),
            ApiOperation(
                method="GET",
                path="/users/{id}",
                operation_id="getUser",
                summary="",
                parameters=(
                    ApiParameter(
                        name="id",
                        location="path",
                        required=True,
                        schema_type="string",
                    ),
                ),
                request_content_types=(),
                response_statuses=("200",),
                security_schemes=(),
            ),
            ApiOperation(
                method="POST",
                path="/users",
                operation_id="createUser",
                summary="",
                parameters=(),
                request_content_types=("application/json",),
                response_statuses=("201",),
                security_schemes=(),
            ),
        ),
        security_scheme_names=(),
    )


class ApiPlannerTests(unittest.TestCase):
    def test_explicit_safe_operations_are_resolved_under_base_path(self):
        selections = select_api_operations(
            inventory=_inventory(),
            selectors=(
                "status",
                "HEAD /health",
            ),
            base_url="https://example.test/api/v1",
        )

        self.assertEqual(
            tuple(
                (
                    item.operation.method,
                    item.url,
                )
                for item in selections
            ),
            (
                (
                    "GET",
                    "https://example.test/api/v1/status",
                ),
                (
                    "HEAD",
                    "https://example.test/api/v1/health",
                ),
            ),
        )

    def test_fallback_selector_is_method_and_path(self):
        operation = _inventory().operations[1]

        self.assertEqual(
            operation_selector(
                operation
            ),
            "HEAD /health",
        )

    def test_required_parameters_are_never_invented(self):
        with self.assertRaisesRegex(
            ValueError,
            "requires parameter values",
        ):
            select_api_operations(
                inventory=_inventory(),
                selectors=("getUser",),
                base_url="https://example.test",
            )

    def test_mutating_operation_is_rejected(self):
        with self.assertRaisesRegex(
            ValueError,
            "blocked method POST",
        ):
            select_api_operations(
                inventory=_inventory(),
                selectors=("createUser",),
                base_url="https://example.test",
            )

    def test_unknown_and_empty_selectors_fail_closed(self):
        with self.assertRaises(ValueError):
            select_api_operations(
                inventory=_inventory(),
                selectors=(),
                base_url="https://example.test",
            )

        with self.assertRaisesRegex(
            ValueError,
            "Unknown API operation selector",
        ):
            select_api_operations(
                inventory=_inventory(),
                selectors=("missing",),
                base_url="https://example.test",
            )

    def test_duplicate_selection_is_deduplicated(self):
        selections = select_api_operations(
            inventory=_inventory(),
            selectors=(
                "status",
                "status",
            ),
            base_url="https://example.test",
        )

        self.assertEqual(
            len(selections),
            1,
        )


if __name__ == "__main__":
    unittest.main()
