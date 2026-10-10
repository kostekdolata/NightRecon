import unittest
from nightrecon_red_engine.process_containment import containment_capabilities
class TestContainment(unittest.TestCase):
    def test_capability_is_explicit(self):
        capabilities=containment_capabilities()
        self.assertIsInstance(capabilities.process_tree_termination,bool)
        self.assertTrue(capabilities.reason)
    def test_windows_not_misrepresented(self):
        capabilities=containment_capabilities()
        if capabilities.platform=="nt":
            self.assertFalse(capabilities.process_tree_termination)
