#include <linux/types.h>
#include <linux/version.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define IPPROTO_UDP 17

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    const __be16 src_port = 0x3500;
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *iph = NULL;
    struct udphdr *udph = NULL;

    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    if (__bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    iph = (struct iphdr *)(data + sizeof(struct ethhdr));

    if ((void *)iph + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    if (iph->protocol != IPPROTO_UDP)
        return XDP_PASS;

    udph = (struct udphdr *)((void *)iph + sizeof(struct iphdr));
    if ((void *)udph + sizeof(struct udphdr) > data_end)
        return XDP_PASS;

    if (udph->source == src_port)
    {
        char fmt[] = "receive dns udp packet\n";
        bpf_trace_printk(fmt, sizeof(fmt));
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = LINUX_VERSION_CODE;