# Architecture

NetSift is a pipeline with strict boundaries:

```text
untrusted bytes → capture container → packet decoder → normalized Packet → filter → report
                  fatal errors       recoverable issues                    pure functions
```

## Design decisions

### Container corruption is fatal; protocol corruption is data

A corrupt record length makes later packet boundaries unknowable, so `pcap.py` raises
`CaptureError`. Once a packet boundary is trustworthy, a truncated DNS or TCP header affects only
that packet. The decoder stores a `ParseIssue` and continues. This prevents one bad frame from
hiding a 10 GB capture while avoiding invented data after a broken container boundary.

Every variable-length read is bounds-checked before unpacking. PCAPNG blocks have a 64 MiB guard,
matching length trailers are required, DNS compression recursion is capped, and IPv6 extension
walking is bounded. These are denial-of-service defenses as much as correctness checks.

### A normalized model separates decoding from presentation

`Packet` owns common endpoints, ports, protocol layers, an information summary, and a `details`
mapping. Renderers do not inspect raw bytes. Adding Markdown output or a web view therefore cannot
change parsing behavior, and adding a decoder does not require changing every output format.

### Filtering stays intentionally small

The filter parser accepts a fixed key allowlist and three operators. It has no `eval`, regex engine,
or implicit precedence. Comma means AND. This is less expressive than BPF, but predictable in shell
scripts and safe for filters accepted from web forms or job parameters.

### Flows are direction independent

Endpoints are formatted with their transport ports and sorted before they become a key. A DNS query
and reply therefore land in one conversation. Protocol is part of the key so a TCP handshake and
subsequent HTTP metadata remain independently visible instead of silently relabeling history.

## Modules

| Module | Responsibility |
| --- | --- |
| `pcap` | Container framing, byte order, timestamps, trusted packet boundaries |
| `protocols` | Bounds-checked layered protocol decoding |
| `models` | Stable domain objects and serialization |
| `filters` | Parse and evaluate the query DSL |
| `flows` | Aggregate direction-independent conversations |
| `render` | Tables, JSON, JSONL, CSV, and hex dumps |
| `demo` | Reproducible packet fixture generation |
| `cli` | Argument validation, I/O orchestration, and exit codes |

## Adding a protocol

1. Start with a minimal valid fixture and expected normalized fields.
2. Add truncation tests at every variable-length boundary.
3. Write a decoder that mutates only the current `Packet`.
4. Append the protocol name only after its identifying structure is valid.
5. Put specialized fields in `packet.details["protocol"]`.
6. Add the dispatch condition and a CLI integration assertion.
7. Run the randomized robustness test before review.

## Trust and privacy

Captures are untrusted, potentially sensitive input. NetSift makes no network calls, loads no
plugins, writes no analysis files implicitly, and does not render terminal control codes from packet
payloads. Operators should still protect exported JSON: hostnames, addresses, and HTTP headers can
contain credentials or personal data.

