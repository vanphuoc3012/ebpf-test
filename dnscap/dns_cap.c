//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

#define MAX_DNS_PKT 512
#define MAX_STATS   8
#define STAT_DNS_CAPTURED 0

// Mirrors the Go struct dnsRawEvent — layout must match byte-for-byte.
struct dns_raw_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u32 pkt_len;
    __u8  payload[MAX_DNS_PKT];
};

// Ring buffer: one entry per captured DNS response.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MiB
} magent_dns SEC(".maps");

// Simple array counter for stats (index 0 = packets captured).
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_STATS);
    __type(key,   __u32);
    __type(value, __u64);
} magent_stats SEC(".maps");

static __always_inline void inc_stat(__u32 idx) {
    __u64 *val = bpf_map_lookup_elem(&magent_stats, &idx);
    if (val)
        __sync_fetch_and_add(val, 1);
}

// socket_filter attached to an AF_PACKET SOCK_DGRAM socket.
// SOCK_DGRAM strips the L2 header, so offset 0 == start of the IP header.
SEC("socket_filter")
int magent_dnscap(struct __sk_buff *skb)
{
    __u8 ver_ihl;
    bpf_skb_load_bytes(skb, 0, &ver_ihl, 1);
    if ((ver_ihl >> 4) != 4)
        return SK_PASS;

    __u8 ihl = (ver_ihl & 0x0F) * 4;
    if (ihl < 20)
        return SK_PASS;

    __u8 protocol;
    bpf_skb_load_bytes(skb, 9, &protocol, 1);
    if (protocol != IPPROTO_UDP)
        return SK_PASS;

    __u32 src_ip, dst_ip;
    bpf_skb_load_bytes(skb, 12, &src_ip, 4);
    bpf_skb_load_bytes(skb, 16, &dst_ip, 4);

    __u16 src_port, dst_port;
    bpf_skb_load_bytes(skb, ihl,     &src_port, 2);
    bpf_skb_load_bytes(skb, ihl + 2, &dst_port, 2);
    src_port = bpf_ntohs(src_port);
    dst_port = bpf_ntohs(dst_port);

    // Only capture DNS responses (server sends from port 53).
    if (src_port != 53)
        return SK_PASS;

    __u32 dns_offset = ihl + 8; // IP header + UDP header (8 bytes)
    __u32 dns_len    = skb->len - dns_offset;

    if (dns_len > MAX_DNS_PKT)
        dns_len = MAX_DNS_PKT;
    if (dns_len < 12) // minimum DNS header size
        return SK_PASS;

    struct dns_raw_event *e = bpf_ringbuf_reserve(&magent_dns, sizeof(*e), 0);
    if (!e)
        return SK_PASS;

    e->src_ip   = src_ip;
    e->dst_ip   = dst_ip;
    e->src_port = 53;
    e->dst_port = dst_port;
    e->pkt_len  = dns_len;

    if (bpf_skb_load_bytes(skb, dns_offset, e->payload, dns_len) < 0) {
        bpf_ringbuf_discard(e, 0);
        return SK_PASS;
    }

    bpf_ringbuf_submit(e, 0);
    inc_stat(STAT_DNS_CAPTURED);
    return SK_PASS;
}

char _license[] SEC("license") = "GPL";
