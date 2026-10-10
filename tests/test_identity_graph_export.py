import unittest
from nightrecon_red_engine.identity_interop import IdentityEvidence,IdentityEdge
from nightrecon_red_engine.identity_graph_export import identity_to_dot
class TestDot(unittest.TestCase):
    def test_deterministic_and_escaped(self):
        graph=IdentityEvidence("test",(IdentityEdge('user"one',"group-a","MemberOf"),))
        result=identity_to_dot(graph)
        self.assertIn('user\\\"one',result)
        self.assertEqual(result,identity_to_dot(graph))
        self.assertIn("digraph RedNightIdentity",result)
    def test_empty(self):
        self.assertEqual(identity_to_dot(IdentityEvidence("test",())).count("->"),0)
