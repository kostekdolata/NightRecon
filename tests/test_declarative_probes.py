"""Tests for declarative service probe packs."""

import base64
import json
import unittest

from nightrecon_red_engine.declarative_probes import (
    load_probe_pack_json,
    match_probe_response,
)


class DeclarativeProbeTests(unittest.TestCase):
    def test_json_probe_pack_is_data_only_and_matches(self):
        pack = json.dumps({
            "probes": [{
                "id": "redis-ping",
                "ports": [6379],
                "payload_base64": base64.b64encode(b"PING\r\n").decode(),
                "response_regex": r"^\+PONG",
                "protocol": "redis",
                "product": "Redis",
                "confidence": "high",
            }]
        })
        probe = load_probe_pack_json(pack)[0]
        result = match_probe_response(probe, b"+PONG\r\n")
        self.assertIsNotNone(result)
        self.assertEqual(result.protocol, "redis")
        self.assertEqual(result.product, "Redis")

    def test_duplicate_probe_ids_are_rejected(self):
        entry = {
            "id": "same",
            "ports": [80],
            "payload_base64": "",
            "response_regex": "HTTP/",
            "protocol": "http",
        }
        with self.assertRaises(ValueError):
            load_probe_pack_json(json.dumps({"probes": [entry, entry]}))


if __name__ == "__main__":
    unittest.main()
