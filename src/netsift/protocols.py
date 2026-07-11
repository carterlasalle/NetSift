"""Bounds-checked decoders for common link, network, and application protocols."""

from __future__ import annotations

import ipaddress
import struct
from collections.abc import Callable

from .models import Packet, ParseIssue


def _need(data: bytes, size: int, layer: str) -> None:
    if len(data) < size:
        raise ValueError(f"truncated {layer}: need {size} bytes, got {len(data)}")


def _mac(raw: bytes) -> str:
    return ":".join(f"{part:02x}" for part in raw)


def _name(protocol: int) -> str:
    return {1: "icmp", 6: "tcp", 17: "udp", 58: "icmpv6"}.get(protocol, f"ip/{protocol}")


def decode_packet(packet: Packet) -> None:
    """Decode *packet* in place; malformed layers become structured issues."""

    try:
        if packet.link_type == 1:
            _ethernet(packet, packet.raw)
        elif packet.link_type == 113:
            _linux_sll(packet, packet.raw)
        elif packet.link_type in {101, 228, 229}:
            version = packet.raw[0] >> 4 if packet.raw else 0
            (_ipv4 if version == 4 else _ipv6)(packet, packet.raw)
        else:
            packet.protocols.append("data")
            packet.info = f"Unsupported link type {packet.link_type} ({len(packet.raw)} bytes)"
    except (IndexError, UnicodeError, struct.error, ValueError) as exc:
        layer = packet.protocols[-1] if packet.protocols else "link"
        packet.issues.append(ParseIssue(layer, str(exc)))
        packet.info = packet.info or "Malformed packet"


def _ethernet(packet: Packet, data: bytes) -> None:
    _need(data, 14, "Ethernet header")
    packet.protocols.append("ethernet")
    destination, source, ether_type = struct.unpack("!6s6sH", data[:14])
    packet.details["ethernet"] = {"source": _mac(source), "destination": _mac(destination)}
    offset = 14
    vlans: list[dict[str, int]] = []
    while ether_type in {0x8100, 0x88A8, 0x9100}:
        _need(data[offset:], 4, "VLAN tag")
        control, ether_type = struct.unpack("!HH", data[offset : offset + 4])
        vlans.append({"id": control & 0x0FFF, "priority": control >> 13})
        offset += 4
    if vlans:
        packet.protocols.append("vlan")
        packet.details["vlan"] = vlans
    _network(packet, ether_type, data[offset:])


def _linux_sll(packet: Packet, data: bytes) -> None:
    _need(data, 16, "Linux cooked header")
    packet.protocols.append("linux-sll")
    packet_type, address_type, address_len = struct.unpack("!HHH", data[:6])
    protocol = struct.unpack("!H", data[14:16])[0]
    packet.details["linux_sll"] = {
        "packet_type": packet_type,
        "address_type": address_type,
        "address": _mac(data[6 : 6 + min(address_len, 8)]),
    }
    _network(packet, protocol, data[16:])


def _network(packet: Packet, ether_type: int, data: bytes) -> None:
    decoder: Callable[[Packet, bytes], None] | None = {
        0x0800: _ipv4,
        0x86DD: _ipv6,
        0x0806: _arp,
    }.get(ether_type)
    if decoder:
        decoder(packet, data)
    else:
        packet.protocols.append("data")
        packet.info = f"EtherType 0x{ether_type:04x} ({len(data)} bytes)"


def _arp(packet: Packet, data: bytes) -> None:
    _need(data, 8, "ARP header")
    packet.protocols.append("arp")
    hardware, protocol, hlen, plen, operation = struct.unpack("!HHBBH", data[:8])
    total = 8 + 2 * hlen + 2 * plen
    _need(data, total, "ARP addresses")
    cursor = 8
    sha, spa = data[cursor : cursor + hlen], data[cursor + hlen : cursor + hlen + plen]
    cursor += hlen + plen
    tha, tpa = data[cursor : cursor + hlen], data[cursor + hlen : cursor + hlen + plen]
    source_ip = str(ipaddress.ip_address(spa)) if protocol == 0x0800 and plen == 4 else spa.hex()
    target_ip = str(ipaddress.ip_address(tpa)) if protocol == 0x0800 and plen == 4 else tpa.hex()
    packet.source, packet.destination = source_ip, target_ip
    packet.details["arp"] = {
        "hardware_type": hardware,
        "protocol_type": protocol,
        "operation": operation,
        "sender_mac": _mac(sha),
        "sender_ip": source_ip,
        "target_mac": _mac(tha),
        "target_ip": target_ip,
    }
    packet.info = (
        f"Who has {target_ip}? Tell {source_ip}"
        if operation == 1
        else f"{source_ip} is at {_mac(sha)}"
    )


def _ipv4(packet: Packet, data: bytes) -> None:
    _need(data, 20, "IPv4 header")
    packet.protocols.append("ipv4")
    version, ihl = data[0] >> 4, (data[0] & 0x0F) * 4
    if version != 4 or ihl < 20:
        raise ValueError("invalid IPv4 version or header length")
    _need(data, ihl, "IPv4 options")
    total_length = struct.unpack("!H", data[2:4])[0]
    if total_length < ihl:
        raise ValueError("IPv4 total length is shorter than header")
    available = min(total_length, len(data))
    protocol = data[9]
    source = str(ipaddress.ip_address(data[12:16]))
    destination = str(ipaddress.ip_address(data[16:20]))
    flags_fragment = struct.unpack("!H", data[6:8])[0]
    fragment_offset = flags_fragment & 0x1FFF
    packet.source, packet.destination = source, destination
    packet.details["ipv4"] = {
        "source": source,
        "destination": destination,
        "ttl": data[8],
        "protocol": protocol,
        "identification": struct.unpack("!H", data[4:6])[0],
        "fragment_offset": fragment_offset,
        "more_fragments": bool(flags_fragment & 0x2000),
    }
    if fragment_offset:
        packet.info = f"IPv4 fragment offset={fragment_offset} protocol={_name(protocol)}"
        return
    _transport(packet, protocol, data[ihl:available])


def _ipv6(packet: Packet, data: bytes) -> None:
    _need(data, 40, "IPv6 header")
    packet.protocols.append("ipv6")
    if data[0] >> 4 != 6:
        raise ValueError("invalid IPv6 version")
    payload_length = struct.unpack("!H", data[4:6])[0]
    next_header = data[6]
    source = str(ipaddress.ip_address(data[8:24]))
    destination = str(ipaddress.ip_address(data[24:40]))
    packet.source, packet.destination = source, destination
    packet.details["ipv6"] = {
        "source": source,
        "destination": destination,
        "hop_limit": data[7],
        "flow_label": int.from_bytes(data[:4], "big") & 0xFFFFF,
    }
    payload = data[40 : min(len(data), 40 + payload_length)]
    extensions: list[int] = []
    for _ in range(12):
        if next_header not in {0, 43, 44, 51, 60}:
            break
        _need(payload, 8, "IPv6 extension header")
        extensions.append(next_header)
        following = payload[0]
        if next_header == 44:
            fragment = struct.unpack("!H", payload[2:4])[0]
            packet.details["ipv6_fragment"] = {
                "offset": (fragment >> 3) & 0x1FFF,
                "more_fragments": bool(fragment & 1),
                "identification": struct.unpack("!I", payload[4:8])[0],
            }
            length = 8
        elif next_header == 51:
            length = (payload[1] + 2) * 4
        else:
            length = (payload[1] + 1) * 8
        _need(payload, length, "IPv6 extension body")
        payload, next_header = payload[length:], following
    else:
        raise ValueError("too many IPv6 extension headers")
    if extensions:
        packet.details["ipv6"]["extension_headers"] = extensions
    _transport(packet, next_header, payload)


def _transport(packet: Packet, protocol: int, data: bytes) -> None:
    if protocol == 6:
        _tcp(packet, data)
    elif protocol == 17:
        _udp(packet, data)
    elif protocol in {1, 58}:
        _icmp(packet, data, protocol == 58)
    else:
        packet.protocols.append(_name(protocol))
        packet.info = f"IP protocol {protocol} ({len(data)} bytes)"


def _tcp(packet: Packet, data: bytes) -> None:
    _need(data, 20, "TCP header")
    packet.protocols.append("tcp")
    source, destination, sequence, acknowledgment = struct.unpack("!HHII", data[:12])
    header_length = (data[12] >> 4) * 4
    if header_length < 20:
        raise ValueError("invalid TCP header length")
    _need(data, header_length, "TCP options")
    flags = data[13]
    names = [
        name
        for bit, name in [
            (1, "FIN"),
            (2, "SYN"),
            (4, "RST"),
            (8, "PSH"),
            (16, "ACK"),
            (32, "URG"),
            (64, "ECE"),
            (128, "CWR"),
        ]
        if flags & bit
    ]
    packet.source_port, packet.destination_port = source, destination
    packet.details["tcp"] = {
        "source_port": source,
        "destination_port": destination,
        "sequence": sequence,
        "acknowledgment": acknowledgment,
        "flags": names,
        "window": struct.unpack("!H", data[14:16])[0],
    }
    payload = data[header_length:]
    packet.info = f"{source} → {destination} [{','.join(names) or 'NONE'}] len={len(payload)}"
    if payload:
        _application(packet, payload, source, destination, tcp=True)


def _udp(packet: Packet, data: bytes) -> None:
    _need(data, 8, "UDP header")
    packet.protocols.append("udp")
    source, destination, length, _checksum = struct.unpack("!HHHH", data[:8])
    if length < 8:
        raise ValueError("invalid UDP length")
    payload = data[8 : min(length, len(data))]
    packet.source_port, packet.destination_port = source, destination
    packet.details["udp"] = {
        "source_port": source,
        "destination_port": destination,
        "length": length,
    }
    packet.info = f"{source} → {destination} len={len(payload)}"
    _application(packet, payload, source, destination, tcp=False)


def _icmp(packet: Packet, data: bytes, ipv6: bool) -> None:
    _need(data, 4, "ICMP header")
    protocol = "icmpv6" if ipv6 else "icmp"
    packet.protocols.append(protocol)
    packet.details[protocol] = {"type": data[0], "code": data[1]}
    packet.info = f"type={data[0]} code={data[1]}"


def _application(
    packet: Packet, payload: bytes, source: int, destination: int, *, tcp: bool
) -> None:
    ports = {source, destination}
    if 53 in ports:
        _dns(packet, payload[2:] if tcp and len(payload) >= 2 else payload)
    elif tcp and (443 in ports or (payload and payload[0] == 0x16)):
        _tls(packet, payload)
    elif tcp and ({80, 8080, 8000} & ports or _looks_http(payload)):
        _http(packet, payload)


def _dns_name(data: bytes, offset: int, *, depth: int = 0) -> tuple[str, int]:
    if depth > 12:
        raise ValueError("DNS compression pointer loop")
    labels: list[str] = []
    end = offset
    jumped = False
    while True:
        _need(data[offset:], 1, "DNS name")
        length = data[offset]
        if length == 0:
            if not jumped:
                end = offset + 1
            break
        if length & 0xC0 == 0xC0:
            _need(data[offset:], 2, "DNS pointer")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if pointer >= len(data):
                raise ValueError("DNS pointer outside message")
            pointed, _ = _dns_name(data, pointer, depth=depth + 1)
            labels.append(pointed)
            if not jumped:
                end = offset + 2
            jumped = True
            break
        if length > 63:
            raise ValueError("invalid DNS label length")
        _need(data[offset + 1 :], length, "DNS label")
        labels.append(data[offset + 1 : offset + 1 + length].decode("ascii"))
        offset += length + 1
        if not jumped:
            end = offset
    return ".".join(labels), end


def _dns(packet: Packet, data: bytes) -> None:
    _need(data, 12, "DNS header")
    packet.protocols.append("dns")
    identifier, flags, questions, answers, authority, additional = struct.unpack(
        "!HHHHHH", data[:12]
    )
    cursor = 12
    names: list[str] = []
    query_types: list[int] = []
    for _ in range(min(questions, 64)):
        name, cursor = _dns_name(data, cursor)
        _need(data[cursor:], 4, "DNS question")
        query_type, _query_class = struct.unpack("!HH", data[cursor : cursor + 4])
        cursor += 4
        names.append(name)
        query_types.append(query_type)
    packet.details["dns"] = {
        "id": identifier,
        "response": bool(flags & 0x8000),
        "opcode": (flags >> 11) & 0xF,
        "rcode": flags & 0xF,
        "questions": names,
        "query_types": query_types,
        "answer_count": answers,
        "authority_count": authority,
        "additional_count": additional,
    }
    kind = "response" if flags & 0x8000 else "query"
    packet.info = f"{kind} {names[0] if names else '<no question>'}"


def _looks_http(payload: bytes) -> bool:
    return payload.startswith(
        (b"GET ", b"POST ", b"PUT ", b"PATCH ", b"DELETE ", b"HEAD ", b"HTTP/")
    )


def _http(packet: Packet, data: bytes) -> None:
    head = data[:16384].split(b"\r\n\r\n", 1)[0]
    lines = head.decode("iso-8859-1").split("\r\n")
    if not lines or not _looks_http(data):
        return
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    packet.protocols.append("http")
    packet.details["http"] = {
        "start_line": lines[0],
        "host": headers.get("host"),
        "headers": headers,
    }
    packet.info = f"{lines[0]}" + (f" host={headers['host']}" if "host" in headers else "")


def _tls(packet: Packet, data: bytes) -> None:
    if len(data) < 9 or data[0] != 22 or data[5] != 1:
        return
    record_length = struct.unpack("!H", data[3:5])[0]
    _need(data, min(record_length + 5, 9), "TLS record")
    hello_length = int.from_bytes(data[6:9], "big")
    body = data[9 : 9 + hello_length]
    _need(body, 34, "TLS ClientHello")
    cursor = 34
    session_length = body[cursor]
    cursor += 1 + session_length
    _need(body[cursor:], 2, "TLS cipher suites")
    cipher_length = struct.unpack("!H", body[cursor : cursor + 2])[0]
    cursor += 2 + cipher_length
    _need(body[cursor:], 1, "TLS compression methods")
    compression_length = body[cursor]
    cursor += 1 + compression_length
    server_name: str | None = None
    alpn: list[str] = []
    versions: list[str] = []
    if len(body) >= cursor + 2:
        extension_length = struct.unpack("!H", body[cursor : cursor + 2])[0]
        cursor += 2
        end = min(len(body), cursor + extension_length)
        while cursor + 4 <= end:
            kind, length = struct.unpack("!HH", body[cursor : cursor + 4])
            value = body[cursor + 4 : cursor + 4 + length]
            if len(value) != length:
                raise ValueError("truncated TLS extension")
            if kind == 0 and len(value) >= 5:
                name_length = struct.unpack("!H", value[3:5])[0]
                server_name = value[5 : 5 + name_length].decode("idna")
            elif kind == 16 and len(value) >= 3:
                pos = 2
                while pos < len(value):
                    size = value[pos]
                    alpn.append(value[pos + 1 : pos + 1 + size].decode("ascii"))
                    pos += size + 1
            elif kind == 43 and len(value) >= 1:
                for pos in range(1, min(len(value), value[0] + 1), 2):
                    if pos + 2 <= len(value):
                        raw = struct.unpack("!H", value[pos : pos + 2])[0]
                        versions.append(
                            {0x0304: "TLS 1.3", 0x0303: "TLS 1.2", 0x0302: "TLS 1.1"}.get(
                                raw, f"0x{raw:04x}"
                            )
                        )
            cursor += 4 + length
    packet.protocols.append("tls")
    packet.details["tls"] = {
        "handshake": "ClientHello",
        "server_name": server_name,
        "alpn": alpn,
        "supported_versions": versions,
    }
    packet.info = "ClientHello" + (f" SNI={server_name}" if server_name else "")
