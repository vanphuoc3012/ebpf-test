
SEC("socket_filter")
int magent_dnscap(struct __sk_buff *skb)
{
    __u8 ver_ihl;
    bpf_skb_load_bytes(skb, 0, &ver_ihl, 1);
    __u8 ip_version = ver_ihl >> 4;
    if (ip_version != 4)
        return SK_PASS;

    __u8 ihl = (ver_ihl & 0x0F) * 4;

    __u8 protocol;
    bpf_skb_load_bytes(skb, 9, &protocol, 1);
    if (protocol != IPPROTO_UDP)
        return SK_PASS;

    __u32 src_ip, dst_ip;
    bpf_skb_load_bytes(skb, 12, &src_ip, 4);
    bpf_skb_load_bytes(skb, 16, &dst_ip, 4);

    __u16 src_port, dst_port;
    bpf_skb_load_bytes(skb, ihl, &src_port, 2);
    bpf_skb_load_bytes(skb, ihl + 2, &dst_port, 2);
    src_port = bpf_ntohs(src_port);
    dst_port = bpf_ntohs(dst_port);

    if (src_port != 53)
        return SK_PASS;

    __u32 dns_offset = ihl + 8;
    __u32 dns_len = skb->len - dns_offset;

    if (dns_len > MAX_DNS_PKT)
        dns_len = MAX_DNS_PKT;
    if (dns_len < 12)
        return SK_PASS;

    struct dns_raw_event *e = bpf_ringbuf_reserve(&magent_dns, sizeof(*e), 0);
    if (!e)
        return SK_PASS;

    e->src_ip = src_ip;
    e->dst_ip = dst_ip;
    e->src_port = 53;
    e->dst_port = dst_port;
    e->pkt_len = dns_len;

    long ret = bpf_skb_load_bytes(skb, dns_offset, e->payload, dns_len);
    if (ret < 0)
    {
        bpf_ringbuf_discard(e, 0);
        return SK_PASS;
    }

    bpf_ringbuf_submit(e, 0);
    inc_stat(STAT_DNS_CAPTURED);

    return SK_PASS;
}