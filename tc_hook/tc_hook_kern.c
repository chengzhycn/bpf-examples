#include <linux/types.h>
#include <linux/version.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_OK 0

SEC("classifier")
int cls(struct __sk_buff *skb)
{
    const __be32 dst_ip = 0x0A0A0A0A; /* 10.10.10.10 */
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    struct iphdr *iph = NULL;

    if (data + sizeof(struct ethhdr) > data_end)
        return TC_ACT_OK;

    if (__bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    iph = (struct iphdr *)(data + sizeof(struct ethhdr));

    if ((void *)iph + sizeof(struct iphdr) > data_end)
        return TC_ACT_OK;

    if (iph->daddr == dst_ip)
    {
        char fmt[] = "send packets to 10.10.10.10\n";
        bpf_trace_printk(fmt, sizeof(fmt));
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = LINUX_VERSION_CODE;
