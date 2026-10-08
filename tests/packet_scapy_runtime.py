"""Non-network runtime checks for the optional Scapy packet backend."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.utils import wrpcap

from nightrecon_red_engine.packet_intelligence import (
    import_pcap,
    observation_from_scapy,
)
from nightrecon_red_engine.syn_scanner import classify_syn_response


def main() -> int:
    packet = IP(src="192.0.2.10", dst="192.0.2.20") / TCP(
        sport=51000,
        dport=80,
        flags="PA",
        seq=100,
    ) / Raw(load=b"GET /health HTTP/1.1\r\nHost: example.test\r\n\r\n")

    observation = observation_from_scapy(packet)
    assert observation is not None
    assert observation.protocol == "http"
    assert observation.http_method == "GET"
    assert observation.http_path == "/health"

    syn_ack = IP(src="192.0.2.20", dst="192.0.2.10") / TCP(
        sport=80,
        dport=51000,
        flags="SA",
    )
    state, confidence, _evidence = classify_syn_response(syn_ack)
    assert state == "open"
    assert confidence == "high"

    rst = IP(src="192.0.2.20", dst="192.0.2.10") / TCP(
        sport=80,
        dport=51000,
        flags="R",
    )
    state, confidence, _evidence = classify_syn_response(rst)
    assert state == "closed"
    assert confidence == "high"

    with TemporaryDirectory(prefix="red-night-packet-") as directory:
        pcap_path = Path(directory) / "fixture.pcap"
        wrpcap(str(pcap_path), [packet])
        imported = import_pcap(str(pcap_path))
        assert len(imported) == 1
        assert imported[0].protocol == "http"

    print("Scapy packet/SYN runtime compatibility: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
