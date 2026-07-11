from __future__ import annotations

import unittest

from netsift.filters import FilterSyntaxError, parse_filter
from netsift.flows import summarize
from netsift.models import Packet


def sample(
    index: int,
    *,
    proto: str = "dns",
    source: str = "10.0.0.1",
    destination: str = "8.8.8.8",
    source_port: int = 50000,
    destination_port: int = 53,
) -> Packet:
    packet = Packet(index, float(index), 60, 60, 1, b"")
    packet.protocols = ["ethernet", "ipv4", "udp", proto]
    packet.source, packet.destination = source, destination
    packet.source_port, packet.destination_port = source_port, destination_port
    packet.details["dns"] = {"questions": ["example.com"]}
    return packet


class FilterTests(unittest.TestCase):
    def test_combines_protocol_port_and_host(self) -> None:
        expression = parse_filter("proto=dns,port=53,host~=EXAMPLE")
        self.assertTrue(expression.matches(sample(1)))

    def test_negates_clause_and_supports_packet_range(self) -> None:
        self.assertTrue(parse_filter("!proto=tls,packet=1-3").matches(sample(2)))

    def test_rejects_unknown_key(self) -> None:
        with self.assertRaisesRegex(FilterSyntaxError, "unknown key"):
            parse_filter("banana=yes")


class FlowTests(unittest.TestCase):
    def test_combines_both_directions(self) -> None:
        outbound = sample(1)
        inbound = sample(
            2, source="8.8.8.8", destination="10.0.0.1", source_port=53, destination_port=50000
        )
        flows = summarize([outbound, inbound])
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].packets, 2)
        self.assertEqual(flows[0].bytes, 120)


if __name__ == "__main__":
    unittest.main()
