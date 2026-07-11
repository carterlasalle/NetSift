from __future__ import annotations

import struct
from pathlib import Path


def write_pcap(path: Path, packets: list[bytes], *, link_type: int = 1) -> Path:
    with path.open("wb") as stream:
        stream.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, link_type))
        for index, packet in enumerate(packets):
            stream.write(struct.pack("<IIII", 1_700_000_000 + index, index * 1000, len(packet), len(packet)))
            stream.write(packet)
    return path

