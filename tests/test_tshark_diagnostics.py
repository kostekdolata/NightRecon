import unittest
from nightrecon_red_engine.tshark_diagnostics import summarize_protocol_diagnostics

class TestProtocolDiagnostics(unittest.TestCase):
    def test_aggregates_without_retaining_sensitive_values(self):
        data=b'[{"_source":{"layers":{"dns":{"dns.flags.rcode":"3","dns.qry.name":"private.example"},"http":{"http.response.code":"404","http.cookie":"secret"}}}}]'
        summary=summarize_protocol_diagnostics(data)
        self.assertEqual(summary.dns_response_codes,(("3",1),))
        self.assertEqual(summary.http_status_codes,(("404",1),))
        self.assertNotIn("private.example",repr(summary))
        self.assertNotIn("secret",repr(summary))

    def test_rejects_invalid_protocol_status(self):
        with self.assertRaises(ValueError):
            summarize_protocol_diagnostics(b'[{"_source":{"layers":{"http":{"http.response.code":"bad"}}}}]')

    def test_rejects_invalid_packet_source(self):
        with self.assertRaises(ValueError):
            summarize_protocol_diagnostics(b'[{"_source":42}]')

    def test_empty_export(self):
        self.assertEqual(summarize_protocol_diagnostics(b"[]").packet_count,0)
