"""Stable human- and machine-readable output formats."""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime

from .flows import Flow
from .models import Packet


def packets_json(packets: list[Packet], *, lines: bool = False) -> str:
    records = [packet.to_dict() for packet in packets]
    if lines:
        return "\n".join(json.dumps(record, separators=(",", ":"), sort_keys=True) for record in records)
    return json.dumps(records, indent=2, sort_keys=True)


def packets_csv(packets: list[Packet]) -> str:
    output = io.StringIO()
    fields = ["index", "timestamp", "source", "destination", "protocol", "length", "malformed", "info"]
    writer = csv.DictWriter(output, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for packet in packets:
        writer.writerow({
            "index": packet.index,
            "timestamp": f"{packet.timestamp:.6f}",
            "source": _endpoint(packet.source, packet.source_port),
            "destination": _endpoint(packet.destination, packet.destination_port),
            "protocol": packet.highest_protocol,
            "length": packet.captured_length,
            "malformed": str(packet.malformed).lower(),
            "info": packet.info,
        })
    return output.getvalue().rstrip()


def packets_table(packets: list[Packet]) -> str:
    rows = []
    for packet in packets:
        moment = datetime.fromtimestamp(packet.timestamp, tz=UTC).strftime("%H:%M:%S.%f")[:-3]
        rows.append([
            str(packet.index), moment, _endpoint(packet.source, packet.source_port),
            _endpoint(packet.destination, packet.destination_port), packet.highest_protocol.upper(),
            str(packet.captured_length), ("! " if packet.malformed else "") + packet.info,
        ])
    return _table(["#", "TIME (UTC)", "SOURCE", "DESTINATION", "PROTO", "BYTES", "INFO"], rows)


def flows_json(flows: list[Flow]) -> str:
    return json.dumps([flow.to_dict() for flow in flows], indent=2, sort_keys=True)


def flows_table(flows: list[Flow]) -> str:
    rows = [[flow.endpoint_a, flow.endpoint_b, flow.protocol.upper(), str(flow.packets), str(flow.bytes), f"{flow.duration:.3f}s"] for flow in flows]
    return _table(["ENDPOINT A", "ENDPOINT B", "PROTO", "PACKETS", "BYTES", "DURATION"], rows)


def hexdump(data: bytes, width: int = 16) -> str:
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset : offset + width]
        hexadecimal = " ".join(f"{byte:02x}" for byte in chunk).ljust(width * 3 - 1)
        printable = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
        lines.append(f"{offset:08x}  {hexadecimal}  |{printable}|")
    return "\n".join(lines)


def _endpoint(address: str | None, port: int | None) -> str:
    if not address:
        return "—"
    if port is None:
        return address
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"


def _table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return "No matching packets."
    widths = [len(header) for header in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = min(70, max(widths[index], len(value)))
    def line(values: list[str]) -> str:
        return "  ".join(value[: widths[index]].ljust(widths[index]) for index, value in enumerate(values)).rstrip()
    return "\n".join([line(headers), line(["─" * width for width in widths]), *(line(row) for row in rows)])

