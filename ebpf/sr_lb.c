/* Copyright (C) 2018 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include <stddef.h>
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>

#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/filter.h>

#include "bpf_helpers.h"

#define LINUX_VERSION_CODE 263682

#ifndef __section
# define __section(x)  __attribute__((section(x), used))
#endif

struct vlan_hdr {
    __u16 h_vlan_TCI;
    __u16 h_vlan_encapsulated_proto;
};

static __always_inline int skb_get_bytes(struct __sk_buff *ctx, unsigned int off,
                                        void *ret, unsigned int retlen) {
    if (ctx == 0) {
        return -1;
    }
    if (ret == 0 || retlen == 0) {
        return -1;
    }

    if (bpf_skb_load_bytes(ctx, off, ret, retlen) < 0) {
        return -1;
    } else {
        if (retlen == sizeof(__u16)) {
            *((__u16 *)ret) = bpf_ntohs(*((__u16 *)ret));
        } else if (retlen == sizeof(__u32)) {
            *((__u32 *)ret) = bpf_ntohl(*((__u32 *)ret));
        }
        return 0;
    }
}


static __always_inline unsigned int ipv4_hash(struct __sk_buff *skb)
{
    if (skb == 0) {
        return 0;
    }

    __u32 nhoff = skb->cb[0];
    __u32 src = 0, dst = 0;

    if (skb_get_bytes(skb, nhoff +  offsetof(struct iphdr, saddr), &src, sizeof(src)) == -1) {
        return 0;
    }
    if (skb_get_bytes(skb, nhoff +  offsetof(struct iphdr, daddr), &dst, sizeof(dst)) == -1) {
        return 0;
    }

    return  src + dst;
}

static inline __u32 ipv6_addr_hash(struct __sk_buff *ctx, __u64 off, __u8 flags)
{
    if (ctx == 0) {
        return 0;
    }

    __u32 w0 = 0, w1 = 0, w2 = 0, w3 = 0;
    if (skb_get_bytes(ctx, off, &w0, sizeof(__u32)) == -1) {
        return 0;
    }
    if (skb_get_bytes(ctx, off + 4, &w1, sizeof(__u32)) == -1) {
        return 0;
    }
    if (skb_get_bytes(ctx, off + 8, &w2, sizeof(__u32)) == -1) {
        return 0;
    }
    if (skb_get_bytes(ctx, off + 12, &w3, sizeof(__u32)) == -1) {
        return 0;
    }

    return (__u32)(w0 ^ w1 ^ w2 ^ w3);
}

static __always_inline unsigned int ipv6_hash(struct __sk_buff *skb)
{
    if (skb == 0) {
        return 0;
    }

    __u32 nhoff;
    __u32 src_hash, dst_hash;

    nhoff = skb->cb[0];
    src_hash = ipv6_addr_hash(skb,
                              nhoff + offsetof(struct ipv6hdr, saddr), 0);
    dst_hash = ipv6_addr_hash(skb,
                              nhoff + offsetof(struct ipv6hdr, daddr), 1);

    return src_hash + dst_hash;
}

int  __section("loadbalancer") sr_lb(struct __sk_buff *skb) {
    __u64 nhoff = 0;
    __u16 proto = bpf_ntohs(skb->protocol);
    __u16 vproto = 0;

    if (skb_get_bytes(skb, ETH_HLEN - ETH_TLEN, &vproto, sizeof(vproto)) == -1) {
        return 0;
    }

    switch (vproto)
    {
    case ETH_P_8021Q:  
    case ETH_P_8021AD:
        nhoff += ETH_HLEN;
        skb_get_bytes(skb, nhoff +  offsetof(struct vlan_hdr, h_vlan_encapsulated_proto), &vproto, sizeof(vproto));
        nhoff += sizeof(struct vlan_hdr);
        switch(vproto) {
            case ETH_P_8021AD:
            case ETH_P_8021Q:
                nhoff += sizeof(struct vlan_hdr);
                skb_get_bytes(skb, nhoff + offsetof(struct vlan_hdr, h_vlan_encapsulated_proto), &vproto, sizeof(vproto));
                //break;
            default:
                proto = vproto;
        }
        skb->cb[0] = nhoff;
        switch (proto) {
            case ETH_P_IP:
                return ipv4_hash(skb);
            case ETH_P_IPV6:
                return ipv6_hash(skb);
            default:
                return 0;
        }
    case ETH_P_IP:      // ipv4
        nhoff += ETH_HLEN;
        skb->cb[0] = nhoff;
        return ipv4_hash(skb);
    case ETH_P_IPV6:    // ipv6
        nhoff += ETH_HLEN;
        skb->cb[0] = nhoff;
        return ipv6_hash(skb);
    default:
        break;
    }

    //layer3
    skb->cb[0] = 0;
    switch (proto) {
        case ETH_P_IP:
            return ipv4_hash(skb);
        case ETH_P_IPV6:
            return ipv6_hash(skb);
        default:
            return 0;
    }
}

char __license[] __section("license") = "GPL";

/* libbpf needs version section to check sync of eBPF code and kernel
 * but socket filter don't need it */
__u32 __version __section("version") = LINUX_VERSION_CODE;
