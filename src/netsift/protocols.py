"""Protocol decoder placeholder, expanded in the next development milestone."""

from .models import Packet


def decode_packet(packet: Packet) -> None:
    """Mark unsupported link data without making the capture unreadable."""

    packet.protocols.append("data")
    packet.info = f"{packet.captured_length} bytes"

