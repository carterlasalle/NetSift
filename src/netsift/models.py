"""Stable data model shared by decoders, filters, and renderers."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class ParseIssue:
    """A recoverable problem in one packet."""

    layer: str
    message: str
    offset: int | None = None


@dataclass(slots=True)
class Packet:
    """A decoded packet with both normalized and protocol-specific fields."""

    index: int
    timestamp: float
    captured_length: int
    original_length: int
    link_type: int
    raw: bytes = field(repr=False)
    protocols: list[str] = field(default_factory=list)
    source: str | None = None
    destination: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    info: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    issues: list[ParseIssue] = field(default_factory=list)

    @property
    def malformed(self) -> bool:
        return bool(self.issues)

    @property
    def highest_protocol(self) -> str:
        return self.protocols[-1] if self.protocols else "unknown"

    def to_dict(self, *, include_raw: bool = False) -> dict[str, Any]:
        result = asdict(self)
        result["malformed"] = self.malformed
        result["highest_protocol"] = self.highest_protocol
        result["timestamp"] = round(self.timestamp, 6)
        if include_raw:
            result["raw"] = self.raw.hex()
        else:
            result.pop("raw", None)
        return result


@dataclass(slots=True)
class Capture:
    """Capture metadata plus an ordered packet stream."""

    format: str
    byte_order: str
    timestamp_resolution: int
    link_type: int
    packets: list[Packet]

