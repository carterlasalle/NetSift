"""Defensive readers for classic PCAP and PCAPNG files."""

from __future__ import annotations

import struct
from pathlib import Path
from typing import BinaryIO

from .models import Capture, Packet, ParseIssue


class CaptureError(ValueError):
    """Raised when the capture container cannot be read safely."""


_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}


def _exact(stream: BinaryIO, size: int, context: str) -> bytes:
    data = stream.read(size)
    if len(data) != size:
        raise CaptureError(f"truncated {context}: expected {size} bytes, got {len(data)}")
    return data


def read_capture(path: str | Path) -> Capture:
    """Read a capture from *path*, rejecting invalid container structures."""

    with Path(path).open("rb") as stream:
        magic = _exact(stream, 4, "capture header")
        if magic in _PCAP_MAGICS:
            return _read_pcap(stream, magic)
        if magic == b"\x0a\x0d\x0d\x0a":
            return _read_pcapng(stream, magic)
        raise CaptureError(f"unsupported capture magic {magic.hex()}")


def _read_pcap(stream: BinaryIO, magic: bytes) -> Capture:
    byte_order, resolution = _PCAP_MAGICS[magic]
    header = _exact(stream, 20, "PCAP global header")
    major, minor, _zone, _sigfigs, snaplen, link_type = struct.unpack(
        f"{byte_order}HHiiii", header
    )
    if (major, minor) != (2, 4):
        raise CaptureError(f"unsupported PCAP version {major}.{minor}")
    if snaplen <= 0:
        raise CaptureError("invalid PCAP snapshot length")

    packets: list[Packet] = []
    while prefix := stream.read(16):
        if len(prefix) != 16:
            raise CaptureError("truncated PCAP packet header")
        seconds, fraction, captured, original = struct.unpack(f"{byte_order}IIII", prefix)
        if captured > snaplen:
            raise CaptureError(f"packet {len(packets) + 1} exceeds snapshot length")
        raw = _exact(stream, captured, f"packet {len(packets) + 1}")
        packet = Packet(
            index=len(packets) + 1,
            timestamp=seconds + fraction / resolution,
            captured_length=captured,
            original_length=original,
            link_type=link_type,
            raw=raw,
        )
        _decode_safely(packet)
        packets.append(packet)
    return Capture("pcap", "little" if byte_order == "<" else "big", resolution, link_type, packets)


def _read_pcapng(stream: BinaryIO, magic: bytes) -> Capture:
    # The byte-order magic is the first reliable endianness signal in PCAPNG.
    head = _exact(stream, 8, "section header")
    raw_length, bom = head[:4], head[4:]
    if bom == b"\x4d\x3c\x2b\x1a":
        order = "<"
    elif bom == b"\x1a\x2b\x3c\x4d":
        order = ">"
    else:
        raise CaptureError("invalid PCAPNG byte-order magic")
    block_length = struct.unpack(f"{order}I", raw_length)[0]
    if block_length < 28 or block_length % 4:
        raise CaptureError("invalid PCAPNG section length")
    rest = _exact(stream, block_length - 12, "section header block")
    if struct.unpack(f"{order}I", rest[-4:])[0] != block_length:
        raise CaptureError("PCAPNG section length mismatch")

    interfaces: list[tuple[int, int]] = []
    packets: list[Packet] = []
    while block_type_raw := stream.read(4):
        if len(block_type_raw) != 4:
            raise CaptureError("truncated PCAPNG block type")
        length = struct.unpack(f"{order}I", _exact(stream, 4, "block length"))[0]
        if length < 12 or length % 4 or length > 64 * 1024 * 1024:
            raise CaptureError(f"invalid PCAPNG block length {length}")
        body_and_tail = _exact(stream, length - 8, "PCAPNG block")
        if struct.unpack(f"{order}I", body_and_tail[-4:])[0] != length:
            raise CaptureError("PCAPNG block length mismatch")
        body = body_and_tail[:-4]
        block_type = struct.unpack(f"{order}I", block_type_raw)[0]
        if block_type == 1 and len(body) >= 8:  # Interface Description Block
            link_type, _reserved, _snaplen = struct.unpack(f"{order}HHI", body[:8])
            interfaces.append((link_type, 1_000_000))
        elif block_type == 6 and len(body) >= 20:  # Enhanced Packet Block
            interface_id, ts_high, ts_low, captured, original = struct.unpack(
                f"{order}IIIII", body[:20]
            )
            if interface_id >= len(interfaces):
                raise CaptureError("packet references unknown PCAPNG interface")
            if captured > len(body) - 20:
                raise CaptureError("truncated enhanced packet data")
            link_type, resolution = interfaces[interface_id]
            packet = Packet(
                index=len(packets) + 1,
                timestamp=((ts_high << 32) | ts_low) / resolution,
                captured_length=captured,
                original_length=original,
                link_type=link_type,
                raw=body[20 : 20 + captured],
            )
            _decode_safely(packet)
            packets.append(packet)
    link_type = interfaces[0][0] if interfaces else 1
    return Capture("pcapng", "little" if order == "<" else "big", 1_000_000, link_type, packets)


def _decode_safely(packet: Packet) -> None:
    try:
        from .protocols import decode_packet

        decode_packet(packet)
    except (IndexError, UnicodeError, struct.error, ValueError) as exc:
        packet.issues.append(ParseIssue("decoder", str(exc)))
        if not packet.info:
            packet.info = "Malformed packet"

