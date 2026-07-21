from dataclasses import dataclass, field, asdict
from typing import Any

@dataclass
class Event:
    type: str
    ts: float
    src_ip: str = ''
    dst_ip: str = ''
    src_mac: str = ''
    dst_mac: str = ''
    protocol: str = ''
    sport: int = 0
    dport: int = 0
    bytes: int = 0
    summary: str = ''
    evidence: dict[str, Any] = field(default_factory=dict)
    def to_dict(self):
        return asdict(self)
