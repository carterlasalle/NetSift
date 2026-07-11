"""NetSift command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from .demo import generate_demo
from .filters import FilterSyntaxError, parse_filter
from .flows import summarize
from .pcap import CaptureError, read_capture
from .render import flows_json, flows_table, hexdump, packets_csv, packets_json, packets_table


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netsift", description="Fast, safe PCAP exploration without Wireshark"
    )
    parser.add_argument("--version", action="version", version="NetSift 0.1.0")
    commands = parser.add_subparsers(dest="command", required=True)

    packets = commands.add_parser("packets", help="list decoded packets")
    packets.add_argument("capture")
    packets.add_argument("-f", "--filter", help="filter DSL, e.g. proto=dns,host~=example")
    packets.add_argument("--format", choices=["table", "json", "jsonl", "csv"], default="table")
    packets.add_argument("--limit", type=_positive_int)
    packets.add_argument("--fail-on-malformed", action="store_true")

    summary = commands.add_parser("summary", help="summarize direction-independent conversations")
    summary.add_argument("capture")
    summary.add_argument("-f", "--filter")
    summary.add_argument("--format", choices=["table", "json"], default="table")
    summary.add_argument("--top", type=_positive_int, default=20)

    inspect = commands.add_parser("inspect", help="show every field for one packet")
    inspect.add_argument("capture")
    inspect.add_argument("index", type=_positive_int)
    inspect.add_argument("--json", action="store_true")
    inspect.add_argument("--hexdump", action="store_true")

    generate = commands.add_parser("generate", help="write a deterministic demo capture")
    generate.add_argument("output", nargs="?", default="demo.pcap")
    generate.add_argument("--force", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "generate":
            print(f"Generated {generate_demo(args.output, force=args.force)}")
            return 0
        capture = read_capture(args.capture)
        if args.command == "inspect":
            if args.index > len(capture.packets):
                raise ValueError(
                    f"packet {args.index} does not exist (capture has {len(capture.packets)})"
                )
            packet = capture.packets[args.index - 1]
            print(json.dumps(packet.to_dict(include_raw=args.json), indent=2, sort_keys=True))
            if args.hexdump:
                print("\nRaw packet\n----------")
                print(hexdump(packet.raw))
            return 0
        selected = parse_filter(args.filter).apply(capture.packets)
        if args.command == "packets":
            if args.limit:
                selected = selected[: args.limit]
            if args.format == "json":
                output = packets_json(selected)
            elif args.format == "jsonl":
                output = packets_json(selected, lines=True)
            elif args.format == "csv":
                output = packets_csv(selected)
            else:
                output = packets_table(selected)
            print(output)
            return (
                2 if args.fail_on_malformed and any(packet.malformed for packet in selected) else 0
            )
        flows = summarize(selected)[: args.top]
        print(flows_json(flows) if args.format == "json" else flows_table(flows))
        return 0
    except (CaptureError, FilterSyntaxError, FileExistsError, OSError, ValueError) as exc:
        print(f"netsift: error: {exc}", file=sys.stderr)
        return 2


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


if __name__ == "__main__":
    raise SystemExit(main())
