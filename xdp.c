//go:build ignore

// xdp.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <arpa/inet.h>

SEC("xdp")
int ping(struct xdp_md *ctx) {
    // Pointers to the start and end of the packet data
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // 1. Parse Ethernet Header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Only process IPv4 packets
    if (eth->h_proto != __builtin_bswap16(ETH_P_IP))
        return XDP_PASS;

    // 2. Parse IP Header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // 3. Check for ICMP (Protocol 1)
    if (ip->protocol == 1) {
        bpf_printk("Hello ping\n");
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";