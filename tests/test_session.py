"""Tests for NightRecon scan sessions."""

import unittest
from uuid import UUID

from nightrecon.session import ScanSession
from nightrecon.targets import parse_target


class ScanSessionTests(unittest.TestCase):
    def test_session_is_created(self):
        target = parse_target("127.0.0.1")

        session = ScanSession.create(
            target=target,
            scope_rules=("127.0.0.1",),
        )

        self.assertEqual(session.target, "127.0.0.1")
        self.assertEqual(session.target_type, "ipv4")
        self.assertEqual(session.scope, ("127.0.0.1",))
        self.assertEqual(session.status, "created")

    def test_session_id_is_valid_uuid(self):
        target = parse_target("example.com")

        session = ScanSession.create(
            target=target,
            scope_rules=("example.com",),
        )

        parsed_uuid = UUID(session.session_id)

        self.assertEqual(str(parsed_uuid), session.session_id)

    def test_session_ids_are_unique(self):
        target = parse_target("127.0.0.1")

        first = ScanSession.create(
            target=target,
            scope_rules=("127.0.0.1",),
        )

        second = ScanSession.create(
            target=target,
            scope_rules=("127.0.0.1",),
        )

        self.assertNotEqual(first.session_id, second.session_id)

    def test_session_converts_to_dictionary(self):
        target = parse_target("10.0.0.1")

        session = ScanSession.create(
            target=target,
            scope_rules=("10.0.0.0/8",),
        )

        data = session.to_dict()

        self.assertEqual(data["target"], "10.0.0.1")
        self.assertEqual(data["target_type"], "ipv4")
        self.assertEqual(data["scope"], ("10.0.0.0/8",))
        self.assertEqual(data["status"], "created")


if __name__ == "__main__":
    unittest.main()
