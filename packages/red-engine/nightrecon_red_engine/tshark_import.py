"""Passive bounded TShark JSON packet summary import, with no command execution."""
import json
from dataclasses import dataclass
MAX_BYTES=8*1024*1024
MAX_PACKETS=10000
@dataclass(frozen=True)
class TsharkSummary:
    source: str
    packets: int
    protocols: tuple[tuple[str,int], ...]
def parse_tshark_json(data:bytes)->TsharkSummary:
    if len(data)>MAX_BYTES: raise ValueError("TShark JSON exceeds limit")
    try: records=json.loads(data)
    except (ValueError,UnicodeError) as exc: raise ValueError("Invalid TShark JSON") from exc
    if not isinstance(records,list) or len(records)>MAX_PACKETS: raise ValueError("Invalid TShark packet list")
    counts={}
    for record in records:
        if not isinstance(record,dict): raise ValueError("Invalid packet")
        layers=record.get("_source",{}).get("layers",{})
        if not isinstance(layers,dict): raise ValueError("Invalid layers")
        for protocol in ("tcp","udp","dns","tls","http","icmp","ipv6"):
            if protocol in layers: counts[protocol]=counts.get(protocol,0)+1
    return TsharkSummary("tshark-json-unverified",len(records),tuple(sorted(counts.items())))
