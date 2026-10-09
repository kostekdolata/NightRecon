"""PCAPNG bounded block parser tests."""
import struct
import unittest
from nightrecon_red_engine.pcapng_import import parse_pcapng, MAX_FILE_BYTES

def block(kind: int, payload: bytes=b"") -> bytes:
    length = 12 + len(payload)
    assert length % 4 == 0
    return struct.pack("<II", kind, length) + payload + struct.pack("<I", length)

class TestPcapng(unittest.TestCase):
    def test_section_and_interface(self):
        section=block(0x0A0D0D0A,struct.pack("<IHHq",0x1A2B3C4D,1,0,-1))
        iface=block(1,struct.pack("<HHI",1,0,65535))
        evidence=parse_pcapng(section+iface)
        self.assertEqual((evidence.sections,evidence.interfaces,evidence.enhanced_packets),(1,1,0))
    def test_rejects_truncated(self):
        section=block(0x0A0D0D0A,struct.pack("<IHHq",0x1A2B3C4D,1,0,-1))
        with self.assertRaisesRegex(ValueError,"length"):
            parse_pcapng(section[:-2])
    def test_rejects_oversize(self):
        with self.assertRaisesRegex(ValueError,"size limit"):
            parse_pcapng(b"x"*(MAX_FILE_BYTES+1))
    def test_rejects_bad_bom(self):
        section=block(0x0A0D0D0A,b"x"*16)
        with self.assertRaisesRegex(ValueError,"byte-order"):
            parse_pcapng(section)
