"""A deliberately small packet-filter language with useful error messages."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Packet


class FilterSyntaxError(ValueError):
    """Raised for a filter that cannot be parsed."""


@dataclass(frozen=True, slots=True)
class Clause:
    key: str
    operator: str
    value: str
    negated: bool = False

    def matches(self, packet: Packet) -> bool:
        actual = _value(packet, self.key)
        if self.operator == "~=":
            result = self.value.casefold() in str(actual).casefold()
        elif self.operator == "!=":
            result = not _equal(actual, self.value)
        else:
            result = _equal(actual, self.value)
        return not result if self.negated else result


@dataclass(frozen=True, slots=True)
class PacketFilter:
    """An AND-combination of filter clauses."""

    clauses: tuple[Clause, ...]

    def matches(self, packet: Packet) -> bool:
        return all(clause.matches(packet) for clause in self.clauses)

    def apply(self, packets: list[Packet]) -> list[Packet]:
        return [packet for packet in packets if self.matches(packet)]


_CLAUSE = re.compile(r"^(?P<not>!)?(?P<key>[a-z_]+)(?P<op>~=|!=|=)(?P<value>.+)$", re.I)
_KEYS = {"proto", "ip", "src", "dst", "port", "host", "malformed", "packet"}


def parse_filter(expression: str | None) -> PacketFilter:
    """Parse comma-separated clauses such as ``proto=dns,host~=example``."""

    if not expression or not expression.strip():
        return PacketFilter(())
    clauses: list[Clause] = []
    for raw in expression.split(","):
        match = _CLAUSE.match(raw.strip())
        if not match:
            raise FilterSyntaxError(f"invalid clause {raw!r}; expected key=value")
        key = match.group("key").lower()
        if key not in _KEYS:
            raise FilterSyntaxError(f"unknown key {key!r}; choose from {', '.join(sorted(_KEYS))}")
        value = match.group("value").strip()
        if not value:
            raise FilterSyntaxError(f"missing value for {key}")
        if key == "malformed" and value.casefold() not in {"true", "false", "yes", "no", "1", "0"}:
            raise FilterSyntaxError("malformed must be true or false")
        clauses.append(Clause(key, match.group("op"), value, bool(match.group("not"))))
    return PacketFilter(tuple(clauses))


def _value(packet: Packet, key: str) -> object:
    if key == "proto":
        return packet.protocols
    if key == "ip":
        return [packet.source, packet.destination]
    if key == "src":
        return packet.source or ""
    if key == "dst":
        return packet.destination or ""
    if key == "port":
        return [packet.source_port, packet.destination_port]
    if key == "host":
        return (
            packet.details.get("http", {}).get("host")
            or packet.details.get("tls", {}).get("server_name")
            or " ".join(packet.details.get("dns", {}).get("questions", []))
        )
    if key == "malformed":
        return packet.malformed
    return packet.index


def _equal(actual: object, expected: str) -> bool:
    if isinstance(actual, list):
        return any(_equal(item, expected) for item in actual)
    if isinstance(actual, bool):
        return actual == (expected.casefold() in {"true", "yes", "1"})
    if isinstance(actual, int):
        if "-" in expected:
            try:
                low, high = (int(part) for part in expected.split("-", 1))
                return low <= actual <= high
            except ValueError:
                return False
        try:
            return actual == int(expected)
        except ValueError:
            return False
    return str(actual).casefold() == expected.casefold()
