import unittest
from nightrecon_red_engine.identity_interop import parse_identity_edges
class TestIdentity(unittest.TestCase):
    def test_valid_relationship(self):
        data=b'{"edges":[{"source":"user-a","target":"group-b","relationship":"MemberOf"}]}'
        self.assertEqual(parse_identity_edges(data).edges[0].relationship,"MemberOf")
    def test_rejects_unapproved_relationship(self):
        with self.assertRaises(ValueError):parse_identity_edges(b'{"edges":[{"source":"a","target":"b","relationship":"Unknown"}]}')
