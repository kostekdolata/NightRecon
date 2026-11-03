import unittest
from nightrecon_red_engine.web_har_import import parse_har
class TestHar(unittest.TestCase):
    def test_secret_minimisation(self):
        data=b'{"log":{"entries":[{"request":{"url":"https://example.org/private?token=abc","method":"GET","headers":[{"name":"Cookie","value":"secret"}]},"response":{"status":200}}]}}'
        result=parse_har(data)
        self.assertEqual(result.requests[0].origin,"https://example.org")
        self.assertNotIn("secret",repr(result))
        self.assertNotIn("token",repr(result))
    def test_invalid_entries(self):
        with self.assertRaises(ValueError):parse_har(b'{"log":{"entries":{}}}')
