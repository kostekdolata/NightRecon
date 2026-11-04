"""Tests for bounded TCP stream reassembly."""

import unittest

from nightrecon_red_engine.tcp_stream_reassembly import (
    TcpSegment,
    reassemble_tcp_segments,
)


class TcpStreamReassemblyTests(unittest.TestCase):
    def test_reassembles_ordered_and_overlapping_segments(self):
        result = reassemble_tcp_segments((
            TcpSegment("p2", 104, b"/ HTTP/1.1\r\n"),
            TcpSegment("p1", 100, b"GET /"),
        ), src_port=51000, dst_port=80)

        self.assertFalse(result.gaps_detected)
        self.assertFalse(result.truncated)
        self.assertGreater(result.bytes_reassembled, 0)
        self.assertIsNotNone(result.protocol)
        self.assertEqual(result.protocol.protocol, "http")
        self.assertEqual(result.protocol.get("method"), "GET")

    def test_gap_is_reported_without_fabricating_bytes(self):
        result = reassemble_tcp_segments((
            TcpSegment("p1", 100, b"abc"),
            TcpSegment("p2", 110, b"xyz"),
        ))
        self.assertTrue(result.gaps_detected)
        self.assertEqual(result.bytes_reassembled, 3)

    def test_stream_byte_limit_truncates(self):
        result = reassemble_tcp_segments((
            TcpSegment("p1", 1, b"abcdefgh"),
        ), max_bytes=4)
        self.assertTrue(result.truncated)
        self.assertEqual(result.bytes_reassembled, 4)


if __name__ == "__main__":
    unittest.main()
