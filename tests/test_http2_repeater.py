"""Tests for scoped HTTP/2 repeater validation."""

import unittest
from unittest.mock import patch

from nightrecon_red_engine.http2_repeater import (
    Http2RuntimeUnavailable,
    replay_http2_request,
)
from nightrecon_shared_core.authorization import Scope


class Http2RepeaterTests(unittest.TestCase):
    def test_http2_repeater_rejects_out_of_scope_target_before_runtime(self):
        scope = Scope.from_values(["example.test"])
        with self.assertRaises(PermissionError):
            replay_http2_request(
                method="GET",
                url="https://other.test/",
                scope=scope,
            )

    def test_http2_repeater_requires_https(self):
        scope = Scope.from_values(["example.test"])
        with self.assertRaises(ValueError):
            replay_http2_request(
                method="GET",
                url="http://example.test/",
                scope=scope,
            )


if __name__ == "__main__":
    unittest.main()
