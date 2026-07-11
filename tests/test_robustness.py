"""Deterministic property-style checks for adversarial decoder input."""

from __future__ import annotations

import random
import unittest

from netsift.models import Packet
from netsift.protocols import decode_packet


class RobustnessTests(unittest.TestCase):
    def test_arbitrary_frames_never_escape_decoder_exceptions(self) -> None:
        randomizer = random.Random(0x4E455453494654)
        link_types = [1, 101, 113, 147, 228, 229]
        for index in range(1_000):
            raw = randomizer.randbytes(randomizer.randrange(0, 768))
            packet = Packet(index, 0.0, len(raw), len(raw), randomizer.choice(link_types), raw)
            decode_packet(packet)
            self.assertTrue(packet.protocols or packet.issues)

    def test_decoder_is_deterministic_for_same_bytes(self) -> None:
        raw = bytes.fromhex("00112233445566778899aabb08004500001400000000400600000a0000010a000002")
        first = Packet(1, 0.0, len(raw), len(raw), 1, raw)
        second = Packet(1, 0.0, len(raw), len(raw), 1, raw)
        decode_packet(first)
        decode_packet(second)
        self.assertEqual(first.to_dict(), second.to_dict())


if __name__ == "__main__":
    unittest.main()
