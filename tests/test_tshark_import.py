import unittest
from nightrecon_red_engine.tshark_import import parse_tshark_json
class TestTshark(unittest.TestCase):
    def test_protocol_summary(self):
        result=parse_tshark_json(b'[{"_source":{"layers":{"ip":{},"tcp":{},"tls":{}}}}]')
        self.assertEqual(result.protocols,(("tcp",1),("tls",1)))
    def test_reject_object(self):
        with self.assertRaises(ValueError):parse_tshark_json(b'{}')
