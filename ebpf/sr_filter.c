// copy filter.c
#include <stddef.h>
#include <linux/bpf.h>

#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <netinet/tcp.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/filter.h>

#include "bpf_helpers.h"
//#include <bpf/bpf_helpers.h>
#define DEBUG 0

#define LINUX_VERSION_CODE 263682
#define SR_PASS       -1
#define SR_FILTER     0
#define MAX_COUNT     512

struct vlan_hdr {
    __u16   h_vlan_TCI;
    __u16   h_vlan_encapsulated_proto;
};

// copy from bpf/bpf_helpers.h
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

struct ipv4_lpm_key {
    __u32 prefixlen;
    __u32 data;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, __u16);
    __uint(map_flags, BPF_F_NO_PREALLOC);  // required
    __uint(max_entries, MAX_COUNT);
} ipv4_lpm_map SEC(".maps");

// 大端转小端
__u32 swap_endian(__u32 value) {
    return ((value >> 24) & 0x000000FF) |      // 取最高字节
           ((value >> 8) & 0x0000FF00) |       // 取次高字节
           ((value << 8) & 0x00FF0000) |       // 取次低字节
           ((value << 24) & 0xFF000000);       // 取最低字节
}

static __always_inline int ipv4_filter(struct __sk_buff *skb)
{
    __u32 nhoff = skb->cb[0];
    __u32 sip = load_word(skb, nhoff + offsetof(struct iphdr, saddr)); // big endian
    __u32 dip = load_word(skb, nhoff + offsetof(struct iphdr, daddr));
    nhoff += sizeof(struct iphdr);

    struct ipv4_lpm_key lookup_key = {
        .prefixlen = 32, // 完整ip
        .data = swap_endian(sip)
    };

    __u16 *value = bpf_map_lookup_elem(&ipv4_lpm_map, &lookup_key);
    if (value) {
        if (*value == 0) {
            #if DEBUG
                char fmt[] = "Found value for saddr: %u %u\n";
                bpf_trace_printk(fmt, sizeof(fmt), sip, *value);
            #endif
            return SR_PASS;
        }

        // 过滤条件存在端口
        __u16 sport = load_half(skb, nhoff + offsetof(struct tcphdr, th_sport));

        char fmt[] = "sport:  %x, value:  %x\n";
        bpf_trace_printk(fmt, sizeof(fmt), sport, *value);

        if (sport == *value) {
             #if DEBUG
                char fmt[] = "Found value for saddr: %u %u %u\n";
                bpf_trace_printk(fmt, sizeof(fmt), sip, sport, *value);
            #endif
            return SR_PASS;
        }
    } else {
        #if DEBUG
            char fmt[] = "No Found value for saddr: %u\n";
            bpf_trace_printk(fmt, sizeof(fmt), sip);
        #endif
    }

    lookup_key.data = swap_endian(dip);
    value = bpf_map_lookup_elem(&ipv4_lpm_map, &lookup_key);
    if (value) {
        if (*value == 0) {
            #if DEBUG
                char fmt[] = "Found value for daddr: %u %u\n";
                bpf_trace_printk(fmt, sizeof(fmt), dip, *value);
            #endif
            return SR_PASS; 
        }

        // 过滤条件存在端口
        __u16 dport = load_half(skb, nhoff + offsetof(struct tcphdr, th_dport));
        if (dport == *value) {
            #if DEBUG
                char fmt[] = "Found value for daddr: %u %u %u\n";
                bpf_trace_printk(fmt, sizeof(fmt), dip, dport, *value);
            #endif
            return SR_PASS;
        }
    } else {
        #if DEBUG
            char fmt[] = "No Found value for daddr: %u\n";
            bpf_trace_printk(fmt, sizeof(fmt), dip);
        #endif
    }

    return SR_FILTER;
}

static __always_inline int ipv6_filter(struct __sk_buff *skb)
{
    return SR_FILTER;
}

int SEC("filter") sr_filter(struct __sk_buff *skb)
{
    __u32 nhoff = ETH_HLEN;

    __u16 proto = load_half(skb, offsetof(struct ethhdr, h_proto));

    if (proto == ETH_P_8021AD || proto == ETH_P_8021Q) {
        proto = load_half(skb, nhoff + offsetof(struct vlan_hdr,
                          h_vlan_encapsulated_proto));
        nhoff += sizeof(struct vlan_hdr);
    }

    skb->cb[0] = nhoff;
    switch (proto) {
        case ETH_P_IP:
            return ipv4_filter(skb);
        case ETH_P_IPV6:
            return ipv6_filter(skb);
        default:
            break;
    }
    return SR_FILTER;
}

char __license[] SEC("license") = "GPL";

__u32 __version SEC("version") = LINUX_VERSION_CODE;
