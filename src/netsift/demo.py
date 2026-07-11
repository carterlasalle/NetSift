"""Deterministic capture generation for demos, smoke tests, and screenshots."""

from __future__ import annotations

import ipaddress
import struct
from pathlib import Path


def generate_demo(path: str | Path, *, force: bool = False) -> Path:
    destination = Path(path)
    if destination.exists() and not force:
        raise FileExistsError(f"{destination} already exists; pass --force to replace it")
    packets = _packets()
    with destination.open("wb") as stream:
        stream.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, packet in enumerate(packets):
            stream.write(
                struct.pack(
                    "<IIII", 1_700_000_000 + index, index * 100_000, len(packet), len(packet)
                )
            )
            stream.write(packet)
    return destination


def _packets() -> list[bytes]:
    mac_a, mac_b = bytes.fromhex("020000000001"), bytes.fromhex("020000000002")
    arp = (
        struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
        + mac_a
        + bytes([10, 0, 0, 10])
        + b"\0" * 6
        + bytes([10, 0, 0, 1])
    )
    question = b"\x07example\x03com\0" + struct.pack("!HH", 1, 1)
    query = struct.pack("!HHHHHH", 0xCAFE, 0x0100, 1, 0, 0, 0) + question
    answer = (
        struct.pack("!HHHHHH", 0xCAFE, 0x8180, 1, 1, 0, 0)
        + question
        + b"\xc0\x0c"
        + struct.pack("!HHIH", 1, 1, 60, 4)
        + bytes([93, 184, 216, 34])
    )
    http = b"GET /portfolio HTTP/1.1\r\nHost: example.com\r\nUser-Agent: NetSift/0.1\r\n\r\n"
    return [
        _eth(mac_b, mac_a, arp, 0x0806),
        _eth(mac_b, mac_a, _ip4(_udp(53000, 53, query), 17, "10.0.0.10", "1.1.1.1")),
        _eth(mac_a, mac_b, _ip4(_udp(53, 53000, answer), 17, "1.1.1.1", "10.0.0.10")),
        _eth(mac_b, mac_a, _ip4(_tcp(51000, 80, b"", 0x02), 6, "10.0.0.10", "93.184.216.34")),
        _eth(mac_b, mac_a, _ip4(_tcp(51000, 80, http, 0x18), 6, "10.0.0.10", "93.184.216.34")),
    ]


def _eth(destination: bytes, source: bytes, payload: bytes, kind: int = 0x0800) -> bytes:
    return destination + source + struct.pack("!H", kind) + payload


def _ip4(payload: bytes, protocol: int, source: str, destination: str) -> bytes:
    return (
        bytes([0x45, 0])
        + struct.pack("!HHHBBH", 20 + len(payload), 1, 0, 64, protocol, 0)
        + ipaddress.ip_address(source).packed
        + ipaddress.ip_address(destination).packed
        + payload
    )


def _udp(source: int, destination: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", source, destination, len(payload) + 8, 0) + payload


def _tcp(source: int, destination: int, payload: bytes, flags: int) -> bytes:
    return struct.pack("!HHIIBBHHH", source, destination, 1, 0, 0x50, flags, 64240, 0, 0) + payload
