// DNS capture userspace: loads the socket_filter eBPF program, attaches it to
// one or more network interfaces, parses DNS responses from the ring buffer, and
// maintains a TTL-aware reverse map of IP → domain for observability.
//
// Build steps:
//
//	cd dnscap
//	go generate          # compiles dns_cap.c → dns_cap_bpf{el,eb}.go + .o
//	go build -o dnscap .
//
// K8s DaemonSet requirements:
//   - securityContext.capabilities.add: [NET_ADMIN, NET_RAW, BPF]
//   - Either hostNetwork: true (to see host interfaces) or specify --ifaces
//   - If running kernel < 5.11 also set: allowPrivilegeEscalation: true

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -target bpf" DnsCap dns_cap.c

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

const maxDNSPkt = 512

// dnsRawEvent mirrors the C struct dns_raw_event.
// Offsets must stay identical to the C definition.
type dnsRawEvent struct {
	SrcIP   uint32
	DstIP   uint32
	SrcPort uint16
	DstPort uint16
	PktLen  uint32
	Payload [maxDNSPkt]byte
}

// ---- reverse-DNS map --------------------------------------------------------

type ipEntry struct {
	Domain  string
	Expires time.Time
}

type RevDNSMap struct {
	mu      sync.RWMutex
	entries map[string]ipEntry // key: IP string
}

func newRevDNSMap() *RevDNSMap {
	return &RevDNSMap{entries: make(map[string]ipEntry)}
}

func (m *RevDNSMap) add(ip, domain string, ttlSec uint32) {
	if ttlSec < 10 {
		ttlSec = 10
	}
	m.mu.Lock()
	m.entries[ip] = ipEntry{
		Domain:  domain,
		Expires: time.Now().Add(time.Duration(ttlSec) * time.Second),
	}
	m.mu.Unlock()
}

func (m *RevDNSMap) snapshot() map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]string, len(m.entries))
	for ip, e := range m.entries {
		out[ip] = e.Domain
	}
	return out
}

func (m *RevDNSMap) cleanup() {
	now := time.Now()
	m.mu.Lock()
	for ip, e := range m.entries {
		if now.After(e.Expires) {
			delete(m.entries, ip)
		}
	}
	m.mu.Unlock()
}

// ---- DNS wire-format parser -------------------------------------------------

// parseDNSName parses a length-encoded DNS name at offset, following
// compression pointers.  Returns the dotted name and the offset of the first
// byte AFTER the name in the original (non-pointer) stream.
func parseDNSName(data []byte, offset int) (string, int, error) {
	var labels []string
	origOffset := -1
	seen := make(map[int]struct{})

	for {
		if offset >= len(data) {
			return "", 0, fmt.Errorf("name parse: offset %d out of bounds", offset)
		}
		if _, loop := seen[offset]; loop {
			return "", 0, fmt.Errorf("name parse: pointer loop at %d", offset)
		}
		seen[offset] = struct{}{}

		b := int(data[offset])
		switch {
		case b == 0: // end
			if origOffset == -1 {
				origOffset = offset + 1
			}
			return strings.Join(labels, "."), origOffset, nil

		case b&0xC0 == 0xC0: // compression pointer
			if offset+1 >= len(data) {
				return "", 0, fmt.Errorf("name parse: pointer truncated at %d", offset)
			}
			if origOffset == -1 {
				origOffset = offset + 2
			}
			offset = int(data[offset]&0x3F)<<8 | int(data[offset+1])

		default: // normal label
			end := offset + 1 + b
			if end > len(data) {
				return "", 0, fmt.Errorf("name parse: label %d+%d exceeds packet", offset+1, b)
			}
			labels = append(labels, string(data[offset+1:end]))
			offset = end
		}
	}
}

type dnsAnswer struct {
	IP  net.IP
	TTL uint32
}

// parseDNSResponse extracts the question QNAME and all A-record answers from a
// DNS response payload (DNS wire format, no IP/UDP headers).
func parseDNSResponse(payload []byte) (qname string, answers []dnsAnswer, err error) {
	if len(payload) < 12 {
		return "", nil, fmt.Errorf("packet too short (%d bytes)", len(payload))
	}

	flags := binary.BigEndian.Uint16(payload[2:4])
	if flags&0x8000 == 0 {
		return "", nil, fmt.Errorf("not a DNS response (QR=0)")
	}
	if rcode := flags & 0x000F; rcode != 0 {
		return "", nil, fmt.Errorf("DNS RCODE=%d", rcode)
	}

	qdCount := int(binary.BigEndian.Uint16(payload[4:6]))
	anCount := int(binary.BigEndian.Uint16(payload[6:8]))
	offset := 12

	// Question section — grab first QNAME, skip rest
	for i := 0; i < qdCount; i++ {
		name, next, e := parseDNSName(payload, offset)
		if e != nil {
			return "", nil, fmt.Errorf("question[%d]: %w", i, e)
		}
		if i == 0 {
			qname = name
		}
		offset = next + 4 // skip QTYPE(2) + QCLASS(2)
		if offset > len(payload) {
			return qname, nil, fmt.Errorf("question section truncated")
		}
	}

	// Answer section
	for i := 0; i < anCount; i++ {
		_, next, e := parseDNSName(payload, offset)
		if e != nil {
			break
		}
		offset = next
		if offset+10 > len(payload) {
			break
		}

		rrType := binary.BigEndian.Uint16(payload[offset : offset+2])
		ttl := binary.BigEndian.Uint32(payload[offset+4 : offset+8])
		rdLen := int(binary.BigEndian.Uint16(payload[offset+8 : offset+10]))
		offset += 10

		if offset+rdLen > len(payload) {
			break
		}
		if rrType == 1 && rdLen == 4 { // A record
			ip := make(net.IP, 4)
			copy(ip, payload[offset:offset+4])
			answers = append(answers, dnsAnswer{IP: ip, TTL: ttl})
		}
		offset += rdLen
	}

	return qname, answers, nil
}

// ---- socket helpers ---------------------------------------------------------

// htons converts a uint16 from host to network (big-endian) byte order.
// golang.org/x/sys/unix does not export Htons, so we implement it inline.
func htons(h uint16) uint16 { return h<<8 | h>>8 }

// u32ToIPString converts a network-byte-order uint32 (from the eBPF struct) to
// a dotted-decimal IPv4 string.
func u32ToIPString(n uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		n&0xFF, (n>>8)&0xFF, (n>>16)&0xFF, (n>>24)&0xFF)
}

// openPacketSocket creates an AF_PACKET SOCK_DGRAM socket bound to ifaceIdx.
// SOCK_DGRAM instructs the kernel to strip L2 headers before calling the eBPF
// filter, so the filter sees offset 0 == start of IP header — matching dns_cap.c.
func openPacketSocket(ifaceIdx int) (int, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM,
		int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return -1, fmt.Errorf("socket: %w (need CAP_NET_RAW)", err)
	}
	sll := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  ifaceIdx,
	}
	if err := unix.Bind(fd, sll); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("bind to ifindex %d: %w", ifaceIdx, err)
	}
	return fd, nil
}

// resolveInterfaces returns the interfaces to attach to.  If names is empty,
// all non-loopback interfaces are returned.
func resolveInterfaces(names string) ([]net.Interface, error) {
	if names != "" {
		var out []net.Interface
		for _, name := range strings.Split(names, ",") {
			name = strings.TrimSpace(name)
			iface, err := net.InterfaceByName(name)
			if err != nil {
				return nil, fmt.Errorf("interface %q: %w", name, err)
			}
			out = append(out, *iface)
		}
		return out, nil
	}
	all, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []net.Interface
	for _, iface := range all {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		out = append(out, iface)
	}
	return out, nil
}

// ---- main -------------------------------------------------------------------

func main() {
	ifacesFlag := flag.String("ifaces", "",
		"Comma-separated interfaces to capture on (default: all non-loopback).\n"+
			"In K8s DaemonSet with hostNetwork:true use e.g. eth0,cni0 or leave empty.")
	httpAddr := flag.String("http", ":9119",
		"Address for the HTTP server (GET /map returns JSON IP→domain, GET /health returns ok)")
	flag.Parse()

	// Raise the memlock limit so eBPF ring buffers and maps can be allocated.
	// On kernels ≥ 5.11 this is a no-op.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("rlimit.RemoveMemlock: %v\n"+
			"Add securityContext.capabilities.add: [BPF] to your DaemonSet.", err)
	}

	var objs DnsCapObjects
	if err := loadDnsCapObjects(&objs, nil); err != nil {
		log.Fatalf("loadDnsCapObjects: %v", err)
	}
	defer objs.Close()

	// Track all raw socket FDs so we can close them on exit.
	var (
		sockMu  sync.Mutex
		sockFDs []int
		attached = make(map[int]struct{}) // ifindex → already attached
	)
	defer func() {
		sockMu.Lock()
		for _, fd := range sockFDs {
			unix.Close(fd)
		}
		sockMu.Unlock()
	}()

	attachIface := func(iface net.Interface) {
		sockMu.Lock()
		_, already := attached[iface.Index]
		sockMu.Unlock()
		if already {
			return
		}

		fd, err := openPacketSocket(iface.Index)
		if err != nil {
			log.Printf("WARN: skip %s: %v", iface.Name, err)
			return
		}
		// SO_ATTACH_BPF = 50; attaches the eBPF program as a socket filter.
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ATTACH_BPF,
			objs.MagentDnscap.FD()); err != nil {
			unix.Close(fd)
			log.Printf("WARN: SO_ATTACH_BPF on %s: %v (need CAP_NET_ADMIN)", iface.Name, err)
			return
		}

		sockMu.Lock()
		sockFDs = append(sockFDs, fd)
		attached[iface.Index] = struct{}{}
		sockMu.Unlock()
		log.Printf("Attached to interface %s (ifindex %d)", iface.Name, iface.Index)
	}

	// Initial attach
	initial, err := resolveInterfaces(*ifacesFlag)
	if err != nil {
		log.Fatalf("resolve interfaces: %v", err)
	}
	if len(initial) == 0 {
		log.Fatal("No interfaces found to attach to. " +
			"In a K8s Pod without hostNetwork:true there may be no visible interfaces.")
	}
	for _, iface := range initial {
		attachIface(iface)
	}

	// In K8s, new veth pairs appear when pods start.  Re-scan every 30 s when
	// the user has not pinned to specific interfaces.
	if *ifacesFlag == "" {
		go func() {
			tick := time.NewTicker(30 * time.Second)
			defer tick.Stop()
			for range tick.C {
				ifaces, err := net.Interfaces()
				if err != nil {
					continue
				}
				for _, iface := range ifaces {
					if iface.Flags&net.FlagLoopback != 0 {
						continue
					}
					attachIface(iface)
				}
			}
		}()
	}

	// Ring buffer → DNS parsing → reverse map
	rbReader, err := ringbuf.NewReader(objs.MagentDns)
	if err != nil {
		log.Fatalf("ringbuf.NewReader: %v", err)
	}
	defer rbReader.Close()

	revMap := newRevDNSMap()

	// TTL expiry cleanup
	go func() {
		tick := time.NewTicker(60 * time.Second)
		defer tick.Stop()
		for range tick.C {
			revMap.cleanup()
		}
	}()

	// HTTP: /map (JSON snapshot) and /health (liveness probe)
	http.HandleFunc("/map", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(revMap.snapshot()); err != nil {
			log.Printf("HTTP /map encode: %v", err)
		}
	})
	http.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	go func() {
		log.Printf("HTTP listening on %s  (GET /map  GET /health)", *httpAddr)
		if err := http.ListenAndServe(*httpAddr, nil); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("HTTP server: %v", err)
		}
	}()

	// Event consumer
	go func() {
		var ev dnsRawEvent
		evSize := int(unsafe.Sizeof(ev))

		for {
			rec, err := rbReader.Read()
			if err != nil {
				if errors.Is(err, os.ErrClosed) {
					return
				}
				log.Printf("ring buffer read: %v", err)
				continue
			}
			if len(rec.RawSample) < evSize {
				log.Printf("short ring buffer record: %d bytes (want %d)", len(rec.RawSample), evSize)
				continue
			}

			if err := binary.Read(bytes.NewReader(rec.RawSample), binary.NativeEndian, &ev); err != nil {
				log.Printf("decode event: %v", err)
				continue
			}

			pktLen := int(ev.PktLen)
			if pktLen > maxDNSPkt {
				pktLen = maxDNSPkt
			}

			qname, answers, err := parseDNSResponse(ev.Payload[:pktLen])
			if err != nil || qname == "" || len(answers) == 0 {
				continue
			}

			clientIP := u32ToIPString(ev.DstIP)
			for _, ans := range answers {
				ip := ans.IP.String()
				revMap.add(ip, qname, ans.TTL)
				log.Printf("dns: client=%-15s  %s → %s  (TTL=%ds)",
					clientIP, qname, ip, ans.TTL)
			}
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("shutting down")
}
