# dnscap

`dnscap` is a small eBPF + Go program that captures DNS **response** packets on a Linux host, sends the raw DNS payload from kernel space to user space through an eBPF ring buffer, parses the DNS message in Go, and maintains a TTL-aware reverse map of:

- `IP -> domain`

It is useful for lightweight DNS observability and for understanding how a Go program can consume structured events produced by eBPF.

---

## What it does

The program has two parts:

1. **eBPF socket filter** (`dns_cap.c`)
   - Attaches to one or more interfaces through `AF_PACKET` sockets.
   - Sees packets starting at the IP header.
   - Filters for:
     - IPv4
     - UDP
     - source port `53`
   - Copies the DNS payload into a ring buffer event.

2. **Go userspace program** (`main.go`)
   - Loads the eBPF program.
   - Attaches it to packet sockets on selected interfaces.
   - Reads events from the ring buffer.
   - Parses DNS wire-format responses.
   - Extracts the first question name and all `A` record answers.
   - Stores results in a TTL-aware in-memory map.
   - Exposes the current map over HTTP.

---

## Current behavior

This implementation currently supports:

- IPv4 DNS responses
- UDP only
- DNS server responses where source port is `53`
- `A` record extraction
- TTL-based expiration of the in-memory reverse map
- HTTP endpoints for health and map inspection

It does **not** currently support:

- IPv6
- DNS over TCP
- DoT / DoH
- `AAAA`, `CNAME`, `MX`, `TXT`, or other RR types
- non-successful DNS responses such as `NXDOMAIN` or `SERVFAIL`
- full raw packet export through HTTP

---

## How the Go program reads eBPF DNS data

The data flow looks like this:

```text
packet on interface
    -> eBPF socket filter inspects packet
    -> eBPF copies DNS payload into ring buffer event
    -> Go reads ring buffer record
    -> Go decodes event struct
    -> Go parses DNS payload
    -> Go logs and stores IP -> domain mapping
```

### 1. eBPF creates an event

The eBPF program writes this event structure into a ring buffer:

```c
struct dns_raw_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u32 pkt_len;
    __u8  payload[MAX_DNS_PKT];
};
```

This contains:

- DNS server source IP
- client destination IP
- ports
- DNS payload length
- raw DNS bytes

### 2. Go mirrors the same struct

The Go program defines the same memory layout:

```go
type dnsRawEvent struct {
    SrcIP   uint32
    DstIP   uint32
    SrcPort uint16
    DstPort uint16
    PktLen  uint32
    Payload [maxDNSPkt]byte
}
```

The layout must match the C struct byte-for-byte.

### 3. Go opens the ring buffer

The userspace code creates a ring buffer reader from the eBPF map:

```go
rbReader, err := ringbuf.NewReader(objs.MagentDns)
```

### 4. Go reads one event at a time

```go
rec, err := rbReader.Read()
```

Then it decodes the raw bytes into the Go struct:

```go
var ev dnsRawEvent
err := binary.Read(bytes.NewReader(rec.RawSample), binary.NativeEndian, &ev)
```

### 5. Go parses the DNS payload

Only the first `PktLen` bytes in `Payload` are valid DNS data:

```go
qname, answers, err := parseDNSResponse(ev.Payload[:pktLen])
```

The parser extracts:

- the first question name (`qname`)
- all IPv4 `A` answers
- TTL for each answer

### 6. Go uses the parsed data

For each `A` record answer, the program:

- logs the event
- stores `answer IP -> qname`
- sets expiration based on TTL

---

## Example end-to-end flow

Suppose a client asks:

```text
google.com A?
```

And receives this DNS response:

```text
google.com -> 142.250.199.14
google.com -> 142.250.199.46
TTL=300
```

The eBPF program captures the UDP response packet and sends an event to the ring buffer.

The Go program reads the event, parses the DNS payload, and gets something equivalent to:

```go
qname = "google.com"
answers = []dnsAnswer{
    {IP: 142.250.199.14, TTL: 300},
    {IP: 142.250.199.46, TTL: 300},
}
```

It then logs lines like:

```text
dns: client=192.168.1.20    google.com -> 142.250.199.14  (TTL=300s)
dns: client=192.168.1.20    google.com -> 142.250.199.46  (TTL=300s)
```

And updates the HTTP-visible map to something like:

```json
{
  "142.250.199.14": "google.com",
  "142.250.199.46": "google.com"
}
```

---

## Requirements

### Runtime platform

This program is **Linux-only**.

It uses:

- Linux eBPF
- Linux packet sockets (`AF_PACKET`)
- Linux kernel headers

It will not run natively on macOS.

### Build-time requirements

You need:

- Go `1.24+`
- `clang`
- Linux kernel headers and BPF headers available for compiling the C eBPF program

### Runtime privileges

The program needs privileges equivalent to:

- `CAP_NET_RAW`
- `CAP_NET_ADMIN`
- `CAP_BPF`

If you are running directly on a Linux host, the simplest way to test is usually with `sudo`.

For container or Kubernetes usage, the code comments expect capabilities like:

- `NET_ADMIN`
- `NET_RAW`
- `BPF`

---

## Build

From the repository root:

```bash
cd dnscap
go generate
go build -o dnscap .
```

### What `go generate` does

This runs `bpf2go` and produces generated Go bindings and compiled eBPF object files from `dns_cap.c`.

Expected generated artifacts look like:

- `dns_cap_bpfel.go`
- `dns_cap_bpfeb.go`
- corresponding `.o` object files

If `go generate` fails, check that:

- `clang` is installed
- Linux/BPF headers are present
- you are building in a Linux environment

---

## Run

### Capture on all non-loopback interfaces

```bash
sudo ./dnscap
```

By default, the program:

- scans all non-loopback interfaces
- attaches to each one
- listens on HTTP `:9119`

### Capture on specific interfaces

```bash
sudo ./dnscap --ifaces eth0,cni0
```

### Change HTTP listen address

```bash
sudo ./dnscap --http :9120
```

### Show help

```bash
./dnscap -h
```

---

## Example startup output

```text
2026/06/24 10:15:01 Attached to interface eth0 (ifindex 2)
2026/06/24 10:15:01 Attached to interface cni0 (ifindex 7)
2026/06/24 10:15:01 HTTP listening on :9119  (GET /map  GET /health)
```

## Example DNS capture output

```text
2026/06/24 10:15:03 dns: client=192.168.1.20    google.com -> 142.250.199.14  (TTL=300s)
2026/06/24 10:15:03 dns: client=192.168.1.20    google.com -> 142.250.199.46  (TTL=300s)
2026/06/24 10:15:05 dns: client=192.168.1.20    api.github.com -> 140.82.114.6  (TTL=60s)
2026/06/24 10:15:08 dns: client=10.42.0.15      kubernetes.default.svc.cluster.local -> 10.96.0.1  (TTL=30s)
```

## Example shutdown output

```text
2026/06/24 10:16:10 shutting down
```

---

## HTTP endpoints

### Health check

```bash
curl http://127.0.0.1:9119/health
```

Example response:

```text
ok
```

### View current IP -> domain map

```bash
curl http://127.0.0.1:9119/map
```

Example response:

```json
{
  "10.96.0.1": "kubernetes.default.svc.cluster.local",
  "140.82.114.6": "api.github.com",
  "142.250.199.14": "google.com",
  "142.250.199.46": "google.com"
}
```

---

## Notes on interface behavior

- If `--ifaces` is not set, the program attaches to all non-loopback interfaces it can find.
- It also periodically rescans interfaces so newly created interfaces can be attached automatically.
- This is useful in environments such as Kubernetes where veth interfaces may appear after startup.

---

## Troubleshooting

### `loadDnsCapObjects` or BPF loading fails

Likely causes:

- not running on Linux
- insufficient privileges
- kernel or BPF feature mismatch
- missing memlock or BPF permissions

### `socket: operation not permitted`

The program needs raw socket privileges.

Try running with `sudo`, or grant the required Linux capabilities.

### `SO_ATTACH_BPF` permission errors

The program needs admin capability to attach the BPF socket filter.

### No DNS events appear

Check the following:

- You are capturing the correct interface.
- DNS traffic is actually plain UDP port 53.
- The host is not using DoH / DoT.
- The responses are IPv4.
- The process has enough privileges.

### Empty `/map`

The map only contains parsed `A` record answers that have not expired yet.

If traffic is:

- `AAAA` only
- failed responses
- encrypted DNS
- expired entries

then `/map` may remain empty.

---

## Summary

`dnscap` is a simple example of using eBPF and Go together:

- eBPF captures DNS response payloads in kernel space
- ring buffer transports those payloads to user space
- Go decodes and parses DNS messages
- the program logs the result and exposes an `IP -> domain` view over HTTP

It is a good base if your goal is:

- capture DNS responses
- consume them from a Go program
- build lightweight DNS observability

If you need more advanced visibility, the next logical extensions would be:

- support `AAAA` and `CNAME`
- expose full parsed response JSON
- support IPv6
- track unsuccessful DNS responses
