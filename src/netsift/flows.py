"""Direction-independent conversation aggregation."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from .models import Packet


@dataclass(slots=True)
class Flow:
    endpoint_a: str
    endpoint_b: str
    protocol: str
    packets: int = 0
    bytes: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    malformed_packets: int = 0

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)

    def to_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["duration"] = round(self.duration, 6)
        return result


def summarize(packets: list[Packet]) -> list[Flow]:
    """Aggregate packets by unordered endpoints and highest useful protocol."""

    flows: dict[tuple[str, str, str], Flow] = {}
    for packet in packets:
        left = _endpoint(packet.source, packet.source_port)
        right = _endpoint(packet.destination, packet.destination_port)
        endpoint_a, endpoint_b = sorted((left, right))
        protocol = packet.highest_protocol
        key = (endpoint_a, endpoint_b, protocol)
        if key not in flows:
            flows[key] = Flow(
                endpoint_a,
                endpoint_b,
                protocol,
                first_seen=packet.timestamp,
                last_seen=packet.timestamp,
            )
        flow = flows[key]
        flow.packets += 1
        flow.bytes += packet.captured_length
        flow.first_seen = min(flow.first_seen, packet.timestamp)
        flow.last_seen = max(flow.last_seen, packet.timestamp)
        flow.malformed_packets += int(packet.malformed)
    return sorted(flows.values(), key=lambda flow: (-flow.bytes, -flow.packets, flow.endpoint_a))


def _endpoint(address: str | None, port: int | None) -> str:
    address = address or "?"
    if port is None:
        return address
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"
