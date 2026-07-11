from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from netsift.pcap import CaptureError, read_capture

from .helpers import write_pcap


class PcapReaderTests(unittest.TestCase):
    def test_reads_classic_pcap_metadata_and_packets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = write_pcap(Path(directory) / "sample.pcap", [b"abc", b"defg"], link_type=147)
            capture = read_capture(path)
        self.assertEqual(capture.format, "pcap")
        self.assertEqual(capture.link_type, 147)
        self.assertEqual([packet.raw for packet in capture.packets], [b"abc", b"defg"])
        self.assertEqual(capture.packets[1].index, 2)

    def test_rejects_unknown_magic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.pcap"
            path.write_bytes(b"not a capture")
            with self.assertRaisesRegex(CaptureError, "unsupported capture magic"):
                read_capture(path)

    def test_rejects_truncated_packet(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "short.pcap"
            path.write_bytes(
                struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
                + struct.pack("<IIII", 1, 0, 20, 20)
                + b"short"
            )
            with self.assertRaisesRegex(CaptureError, "truncated packet 1"):
                read_capture(path)

    def test_reads_pcapng_enhanced_packet(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.pcapng"
            packet = b"opaque"
            section = struct.pack("<II IHHq I", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28)
            interface = struct.pack("<IIHHII", 1, 20, 147, 0, 65535, 20)
            padded = packet + b"\0" * ((-len(packet)) % 4)
            length = 32 + len(padded)
            enhanced = (
                struct.pack("<IIIIIII", 6, length, 0, 0, 1_000_000, len(packet), len(packet))
                + padded
                + struct.pack("<I", length)
            )
            path.write_bytes(section + interface + enhanced)
            capture = read_capture(path)
        self.assertEqual(capture.format, "pcapng")
        self.assertEqual(capture.packets[0].raw, packet)
        self.assertEqual(capture.packets[0].timestamp, 1.0)


if __name__ == "__main__":
    unittest.main()
