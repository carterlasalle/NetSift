from __future__ import annotations

import ipaddress
import struct
import unittest

from netsift.models import Packet
from netsift.protocols import decode_packet


def ethernet(payload: bytes, ether_type: int = 0x0800) -> bytes:
    return bytes.fromhex("00112233445566778899aabb") + struct.pack("!H", ether_type) + payload


def ipv4(
    payload: bytes, protocol: int, source: str = "10.0.0.1", destination: str = "8.8.8.8"
) -> bytes:
    return (
        bytes([0x45, 0])
        + struct.pack("!H", 20 + len(payload))
        + struct.pack("!HH", 7, 0)
        + bytes([64, protocol])
        + b"\0\0"
        + ipaddress.ip_address(source).packed
        + ipaddress.ip_address(destination).packed
        + payload
    )


def packet(raw: bytes, link_type: int = 1) -> Packet:
    value = Packet(1, 0.0, len(raw), len(raw), link_type, raw)
    decode_packet(value)
    return value


class ProtocolTests(unittest.TestCase):
    def test_decodes_dns_query(self) -> None:
        question = b"\x07example\x03com\0" + struct.pack("!HH", 1, 1)
        dns = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + question
        udp = struct.pack("!HHHH", 53000, 53, len(dns) + 8, 0) + dns
        result = packet(ethernet(ipv4(udp, 17)))
        self.assertEqual(result.protocols, ["ethernet", "ipv4", "udp", "dns"])
        self.assertEqual(result.details["dns"]["questions"], ["example.com"])
        self.assertEqual((result.source_port, result.destination_port), (53000, 53))

    def test_decodes_vlan_and_tcp_flags(self) -> None:
        tcp = struct.pack("!HHIIBBHHH", 44444, 443, 1, 0, 0x50, 0x02, 65535, 0, 0)
        frame = (
            bytes.fromhex("00112233445566778899aabb")
            + struct.pack("!HHH", 0x8100, 42, 0x0800)
            + ipv4(tcp, 6)
        )
        result = packet(frame)
        self.assertEqual(result.details["vlan"][0]["id"], 42)
        self.assertEqual(result.details["tcp"]["flags"], ["SYN"])

    def test_decodes_arp_request(self) -> None:
        arp = (
            struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
            + bytes.fromhex("66778899aabb")
            + bytes([10, 0, 0, 1])
            + b"\0" * 6
            + bytes([10, 0, 0, 2])
        )
        result = packet(ethernet(arp, 0x0806))
        self.assertEqual(result.highest_protocol, "arp")
        self.assertIn("Who has 10.0.0.2", result.info)

    def test_malformed_packet_is_nonfatal(self) -> None:
        result = packet(b"short")
        self.assertTrue(result.malformed)
        self.assertIn("truncated Ethernet", result.issues[0].message)

    def test_unsupported_link_type_is_visible(self) -> None:
        result = packet(b"opaque", link_type=147)
        self.assertEqual(result.highest_protocol, "data")
        self.assertIn("Unsupported link type", result.info)


if __name__ == "__main__":
    unittest.main()
