# NetSift

[![CI](https://github.com/carterlasalle/NetSift/actions/workflows/ci.yml/badge.svg)](https://github.com/carterlasalle/NetSift/actions/workflows/ci.yml)
[![Security](https://github.com/carterlasalle/NetSift/actions/workflows/security.yml/badge.svg)](https://github.com/carterlasalle/NetSift/actions/workflows/security.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-22c55e.svg)](LICENSE)

NetSift turns packet captures into answers from the terminal. It reads PCAP and PCAPNG files,
defensively decodes common network protocols, filters packets with a compact query language, and
builds direction-independent conversation summaries. The core has no runtime dependencies.

```text
$ netsift packets demo.pcap --filter 'proto=dns,host~=example'
#  TIME (UTC)    SOURCE           DESTINATION      PROTO  BYTES  INFO
─  ────────────  ───────────────  ───────────────  ─────  ─────  ────────────────────
2  22:13:21.100  10.0.0.10:53000  1.1.1.1:53      DNS    71     query example.com
3  22:13:22.200  1.1.1.1:53       10.0.0.10:53000 DNS    87     response example.com
```

## Why it stands out

- Safe by design: malformed protocol data is attached to a packet as a structured issue; corrupt
  capture containers fail with a precise error instead of producing misleading output.
- Useful at both the terminal and API boundary: tables for humans; deterministic JSON, JSONL, and
  CSV for shell pipelines and automation.
- Real protocol depth: stacked VLAN, Linux cooked capture, IPv4 fragmentation, IPv6 extension
  headers, TCP/UDP/ICMP, DNS compression, HTTP metadata, and TLS ClientHello SNI/ALPN.
- Reproducible: `netsift generate` creates a deterministic five-packet capture for demos and tests.
- Tested as a product: unit, integration, randomized robustness, CLI smoke, formatting, type, and
  packaging checks run in CI on Linux, macOS, and Windows.

NetSift never captures live traffic and never needs elevated privileges. It operates on files you
already own, making the trust boundary small and reviewable.

## Install

NetSift requires Python 3.11 or newer.

```bash
git clone https://github.com/carterlasalle/NetSift.git
cd NetSift
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
python -m pip install -e .
netsift --help
```

For an isolated command, install with `pipx install .` from the checkout.

## Quick tour

Create a known-good capture and inspect it:

```bash
netsift generate demo.pcap
netsift packets demo.pcap
netsift summary demo.pcap --top 10
netsift inspect demo.pcap 5 --hexdump
```

Use structured output in a pipeline:

```bash
netsift packets traffic.pcap --filter 'proto=tls' --format jsonl \
  | jq -r '.details.tls.server_name // empty' \
  | sort -u

netsift packets traffic.pcap --filter 'malformed=true' --format json \
  > malformed-packets.json
```

Make malformed input fail a CI or forensic pipeline:

```bash
netsift packets upload.pcap --fail-on-malformed >/dev/null
```

Exit code `0` means success. Input, syntax, or container errors return `2`; with
`--fail-on-malformed`, decoded packet issues also return `2` after output is written.

## Commands

| Command | Purpose | Formats |
| --- | --- | --- |
| `packets CAPTURE` | Decode and list packets | table, JSON, JSONL, CSV |
| `summary CAPTURE` | Rank bidirectional conversations by bytes | table, JSON |
| `inspect CAPTURE INDEX` | Show normalized and protocol-specific fields | JSON, optional hex dump |
| `generate [OUTPUT]` | Create a deterministic demo PCAP | PCAP |

Run `netsift COMMAND --help` for every option.

## Filter language

Filters are comma-separated AND clauses. Values are case-insensitive. `=` tests equality, `~=`
tests substring containment, `!=` tests inequality, and a leading `!` negates the whole clause.

| Key | Meaning | Example |
| --- | --- | --- |
| `proto` | Any decoded protocol layer | `proto=dns` |
| `ip` | Either network endpoint | `ip=10.0.0.10` |
| `src`, `dst` | Directional network endpoint | `src=192.0.2.5` |
| `port` | Either transport port | `port=443` |
| `host` | DNS question, HTTP Host, or TLS SNI | `host~=example` |
| `malformed` | Whether parsing produced an issue | `malformed=true` |
| `packet` | Exact packet number or inclusive range | `packet=20-40` |

Examples:

```bash
netsift packets capture.pcap -f 'proto=dns,port=53'
netsift packets capture.pcap -f 'proto=tls,host~=internal'
netsift packets capture.pcap -f '!proto=arp,packet=1-200'
```

The language intentionally does not execute code or regular expressions. See
[architecture.md](docs/architecture.md) for the reasoning and extension points.

## Protocol support

| Layer | Supported |
| --- | --- |
| Capture | Classic PCAP (micro/nanosecond, both byte orders), PCAPNG enhanced packets |
| Link | Ethernet II, stacked 802.1Q/802.1ad VLAN, Linux SLL v1, raw IP |
| Network | ARP, IPv4, IPv6 and common extension headers |
| Transport | TCP, UDP, ICMPv4, ICMPv6 |
| Application | DNS questions, HTTP/1 start line and headers, TLS ClientHello metadata |

Encrypted payloads stay encrypted. NetSift extracts only unencrypted handshake metadata already
present in the capture and makes no attempt to bypass TLS.

## Python API

```python
from netsift import read_capture
from netsift.filters import parse_filter
from netsift.flows import summarize

capture = read_capture("traffic.pcapng")
dns_packets = parse_filter("proto=dns").apply(capture.packets)
for conversation in summarize(dns_packets):
    print(conversation.to_dict())
```

`Packet.to_dict()` is the stable serialization boundary. Protocol-specific values live under
`details`; recoverable decoder errors live under `issues`. Raw payload bytes are excluded unless
explicitly requested.

## Development

The runtime is dependency-free. Developer tooling is optional:

```bash
python -m pip install -e '.[dev]'
python -m unittest discover -v
ruff check .
ruff format --check .
mypy src
python -m build
```

The suite follows a test-first shape: fixtures express expected wire behavior, decoders implement
the smallest safe interpretation, and randomized inputs prove the public decoder does not crash.
See [CONTRIBUTING.md](CONTRIBUTING.md) for the protocol change checklist.

## Scope and roadmap

NetSift is an explorer, not a replacement for Wireshark or an intrusion-detection system. Planned
extensions include TCP stream reassembly, richer DNS answers, QUIC Initial metadata, pluggable
decoders, and optional live capture behind an explicit privilege boundary.

Security-sensitive bugs should follow [SECURITY.md](SECURITY.md). Design trade-offs and data flow
are documented in [docs/architecture.md](docs/architecture.md).

## License

MIT © Carter LaSalle. See [LICENSE](LICENSE).

