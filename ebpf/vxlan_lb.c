#include <stddef.h>
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>

#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/filter.h>
#include <linux/udp.h>

#include "bpf_helpers.h"

#define LINUX_VERSION_CODE 263682
#define DEBUG 0

#ifndef __section
# define __section(x)  __attribute__((section(x), used))
#endif

struct vlan_hdr {
    __u16 h_vlan_TCI;
    __u16 h_vlan_encapsulated_proto;
};

// 取自 linux-headers-$(uname -r) 中 vxlan.h 头文件定义
//    因为存在编译问题所以将结构体单独提取出来
struct vxlanhdr {
	__be32 vx_flags;
	__be32 vx_vni;
};
#ifndef VXLAN_HF_VNI
    // 这个宏定义也是头文件 vxlan.h 存在的
    #define VXLAN_HF_VNI (1 << 27)
#endif

#define SR_DROP 0

/**
 * @brief 从 skb 对应的数据包的指定偏移处取出数据
 * 
 * @param ctx    skb 对象 
 * @param off    偏移
 * @param ret    返回值
 * @param retlen 返回值的长度
 * @retval 0 成功
 * @retval -1 失败
 */
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

/**
 * @brief 获取三层 header 的偏移值
 * 
 * @param skb      数据帧所属的 sk buffer
 * @param l2_off   二层 header 的偏移值
 * @param l3_proto 三层协议类型
 * @param l3_off   三层 header 的偏移值（返回结果）
 * 
 * @retval -1：出错，l3_proto 和 l3_off 无论是什么值都无效
 * @retval 0：成功
 */
static __always_inline int get_l3_offset(struct __sk_buff *skb, unsigned int l2_off, unsigned short l3_proto, unsigned int *l3_off) {
    if (skb == 0 || l3_off == 0) {
        return -1;
    }

    /*
     * 对于 Q-in-Q 报文，实测客户环境是：
     *
     * +-----------+-----------+-----------+-------------+-------------+------------------+
     * |   DMAC    |   SMAC    |   ETPE    |  VLAN TAG1  |  VLAN TAG2  |     Payload      |
     * |  6 Bytes  |  6 Bytes  |  2 Bytes  |   4 Bytes   |   4 Bytes   |  Variable length |
     * +-----------+-----------+-----------+-------------+-------------+------------------+
     * |                          0x8100   |   0x8100        0x0800
     * \______________  ___________________/
     *                \/
     *           以太网帧 header
     * 
     * 根据 802.1ad，ETPE 应该是 0x88A8；但客户环境 ETPE 是 0x8100
     * 参考 https://support.huawei.com/enterprise/en/doc/EDOC1100174721/e4e9d43e/qinq-frame-format
     * 可知不同厂商（vendor）有不同取值
     *   - 0x8100: 华为
     *   - 0x88a8: IEEE 802.1ad 标准的设备
     *   - 0x9100: Juniper
     *   - 0x9200: 少数几个厂商
     * 
     * FIXME: 现在 QiQ 只考虑华为的场景，其他场景后续再迭代
     */

    int ret = 0;
    switch (l3_proto) {
    case ETH_P_8021Q: // vlan
        if (skb_get_bytes(skb, l2_off + offsetof(struct vlan_hdr, h_vlan_encapsulated_proto), &l3_proto, sizeof(l3_proto)) == -1) {
#ifdef DEBUG
            char fmt0[] = "[LB] 0: fetch vlan.tpid from skb failed \n";
            bpf_trace_printk(fmt0, sizeof(fmt0));
#endif
            return -1;
        }
        *l3_off = l2_off + sizeof(struct vlan_hdr);
        if (l3_proto == ETH_P_8021Q) {
            // 华为设备的 QiQ 逻辑
            if (skb_get_bytes(skb, l2_off + sizeof(struct vlan_hdr) + offsetof(struct vlan_hdr, h_vlan_encapsulated_proto), &l3_proto, sizeof(l3_proto)) == -1) {
#ifdef DEBUG
                char fmt0[] = "[LB] 0: fetch huawei-qiq.tpid from skb failed \n";
                bpf_trace_printk(fmt0, sizeof(fmt0));
#endif
                return -1;
            }
            *l3_off += sizeof(struct vlan_hdr);
        }
        break;
    case ETH_P_8021AD: // vlan Q-in-Q
        // FIXME: 未经过测试
        if (skb_get_bytes(skb, l2_off + sizeof(struct vlan_hdr) + offsetof(struct vlan_hdr, h_vlan_encapsulated_proto), &l3_proto, sizeof(l3_proto)) == -1) {
#ifdef DEBUG
            char fmt0[] = "[LB] 0: fetch qiq.tpid from skb failed \n";
            bpf_trace_printk(fmt0, sizeof(fmt0));
#endif
            return -1;
        }
        *l3_off = l2_off + sizeof(struct vlan_hdr) + sizeof(struct vlan_hdr);
        break;
    case ETH_P_IPV6: // ipv6
        *l3_off = l2_off;
#ifdef DEBUG
        char fmt0[] = "[LB] 0: ipv6 \n";
        bpf_trace_printk(fmt0, sizeof(fmt0));
#endif
        break;
    case ETH_P_IP: // ipv4
        *l3_off = l2_off;
#ifdef DEBUG
        char fmt1[] = "[LB] 0: ipv4 \n";
        bpf_trace_printk(fmt1, sizeof(fmt1));
#endif
        break;
    default:
        ret = -1; // FIXME: 其他三层协议暂时返回 -1
#ifdef DEBUG
        char fmt2[] = "[LB] 0: other l3 l3_proto (0x%x) \n";
        bpf_trace_printk(fmt2, sizeof(fmt2), l3_proto);
#endif
        break;
    }

    return ret;
}

/**
 * @brief 判断是否 vxlan 报文
 * 
 * @param skb      sk buffer
 * @param l3_proto 三层协议，调用时需要先传入三层协议，如果当前报文外层是 vxlan，
 *                 则会更新为内层的协议（返回值）
 * @param l3_off   三层 header 的偏移值，调用时需要先传入三层 header 的偏移值，
 *                 如果当前报文外层是 vxlan，则会更新为内层的三层 header 偏移（返回值）
 * 
 * @retval -1 出错，l3_proto 和 l3_off 不变
 * @retval 0  不是 vxlan 报文，l3_proto 和 l3_off 不变
 * @retval 1  是 vxlan 报文，l3_proto 和 l3_off 会更正为内层数据
 */
static __always_inline int check_vxlan(struct __sk_buff *skb, unsigned short *l3_proto, unsigned int *l3_off) {
    if (skb == 0 || l3_proto == 0 || l3_off == 0) {
        return -1;
    }

    __u8 l4_proto = 0;
    if (*l3_proto == ETH_P_IP) {
        if (skb_get_bytes(skb, *l3_off + offsetof(struct iphdr, protocol), &l4_proto, sizeof(l4_proto)) == -1) {
            return -1;
        }
    } else if (*l3_proto == ETH_P_IPV6) {
        if (skb_get_bytes(skb, *l3_off + offsetof(struct ipv6hdr, nexthdr), &l4_proto, sizeof(l4_proto)) == -1) {
            return -1;
        }
    } else {
        // 暂时不考虑其他三层协议
        return -1;
    }

    if (l4_proto == IPPROTO_UDP) {
        __u8 ip_ver_hlen = 0;
        if (skb_get_bytes(skb, *l3_off, &ip_ver_hlen, sizeof(ip_ver_hlen)) == -1) {
            return -1;
        }
        __u32 ip_hlen = 0;
#if defined(__LITTLE_ENDIAN_BITFIELD)
        ip_hlen = (ip_ver_hlen & 0xf) << 2;
#elif defined (__BIG_ENDIAN_BITFIELD)
        // FIXME: 未经过测试
        ip_hlen = (ip_ver_hlen & 0xf0) << 2;
#else
#error	"Please fix <asm/byteorder.h>"
#endif

        __u32 vxlan_flags = 0;
        __u32 vxlan_off = 0;
        if (*l3_proto == ETH_P_IP) {
            vxlan_off = *l3_off + ip_hlen + sizeof(struct udphdr);
        } else if (*l3_proto == ETH_P_IPV6) {
            vxlan_off = *l3_off + sizeof(struct ipv6hdr) + sizeof(struct udphdr);
        } else {
            // 暂时不考虑其他三层协议
            return -1;
        }
        if (skb_get_bytes(skb, vxlan_off, &vxlan_flags, sizeof(__u32)) == -1) {
            return -1;
        } else {
            if ((vxlan_flags & VXLAN_HF_VNI) == VXLAN_HF_VNI) {
                // l3_proto 和 l3_off 只有在这里才会更新
                *l3_off = vxlan_off + sizeof(struct vxlanhdr);
                if (skb_get_bytes(skb, *l3_off + offsetof(struct ethhdr, h_proto), l3_proto, sizeof(*l3_proto)) == -1) {
                    return SR_DROP;
                }
                *l3_off += ETH_HLEN;
#ifdef DEBUG
                char fmt2[] = "[LB] 2: vxlan inner.l3.proto=0x%x, inner.l3.nhoff=0x%x\n";
                bpf_trace_printk(fmt2, sizeof(fmt2), *l3_proto, *l3_off);
#endif
                return 1;
            }
        }
    }

    return 0;
}

static __always_inline unsigned int ipv4_hash(struct __sk_buff *skb)
{
    if (skb == 0) {
        return SR_DROP;
    }

    __u32 nhoff = skb->cb[0];
    __u32 src = 0, dst = 0;

    if (skb_get_bytes(skb, nhoff +  offsetof(struct iphdr, saddr), &src, sizeof(src)) == -1) {
        return SR_DROP;
    }
    if (skb_get_bytes(skb, nhoff +  offsetof(struct iphdr, daddr), &dst, sizeof(dst)) == -1) {
        return SR_DROP;
    }

#ifdef DEBUG
    char fmt3[] = "[LB] 3: l3.src=0x%x, l3.dst=0x%x\n";
    bpf_trace_printk(fmt3, sizeof(fmt3), src, dst);
#endif

    return  src + dst;
}

static inline __u32 ipv6_addr_hash(struct __sk_buff *ctx, __u64 off, __u8 flags)
{
    if (ctx == 0) {
        return SR_DROP;
    }

    __u32 w0 = 0, w1 = 0, w2 = 0, w3 = 0;
    if (skb_get_bytes(ctx, off, &w0, sizeof(__u32)) == -1) {
        return SR_DROP;
    }
    if (skb_get_bytes(ctx, off + 4, &w1, sizeof(__u32)) == -1) {
        return SR_DROP;
    }
    if (skb_get_bytes(ctx, off + 8, &w2, sizeof(__u32)) == -1) {
        return SR_DROP;
    }
    if (skb_get_bytes(ctx, off + 12, &w3, sizeof(__u32)) == -1) {
        return SR_DROP;
    }

    return (__u32)(w0 ^ w1 ^ w2 ^ w3);
}

static __always_inline unsigned int ipv6_hash(struct __sk_buff *skb)
{
    if (skb == 0) {
        return SR_DROP;
    }

    __u32 nhoff;
    __u32 src_hash, dst_hash;

    nhoff = skb->cb[0];
    src_hash = ipv6_addr_hash(skb,
                              nhoff + offsetof(struct ipv6hdr, saddr), 0);
    dst_hash = ipv6_addr_hash(skb,
                              nhoff + offsetof(struct ipv6hdr, daddr), 1);

#ifdef DEBUG
    char fmt3[] = "[LB] 3: src_hash=0x%x, dst_hash=0x%x\n";
    bpf_trace_printk(fmt3, sizeof(fmt3), src_hash, dst_hash);
#endif

    return src_hash + dst_hash;
}

int __section("loadbalancer") lb(struct __sk_buff *skb) {
    if (skb == 0) {
        return SR_DROP;
    }

    __u16 ret = SR_DROP;
    __u16 proto = 0;
    __u32 nhoff = 0;

    if (skb_get_bytes(skb, offsetof(struct ethhdr, h_proto), &proto, sizeof(proto)) == -1) {
        return SR_DROP;
    }
    // 开发环境与公司内网环境对于报文的偏移有区别，有的环境报文 0 字节处是二层 header，
    // 有的环境则没有二层 header，因此：
    //
    // 第一次假设 0 字节处是二层 header，获取三层 header 偏移
    if (get_l3_offset(skb, ETH_HLEN, proto, &nhoff) == -1) {
        proto = bpf_ntohs(skb->protocol);
        // 第二次假设 0 字节处是三层 header 或者 vlan、vxlan header 等，获取三层 header 偏移
        if (get_l3_offset(skb, 0, proto, &nhoff) == -1) {
            return SR_DROP;
        }
    }

#ifdef DEBUG
    char fmt1[] = "[LB] 1: l3.proto=0x%x, l3.nhoff=0x%x\n";
    bpf_trace_printk(fmt1, sizeof(fmt1), proto, nhoff);
#endif

    // 判断是否隧道协议，如果是还要跳过外层隧道头
    int flag_vxlan = check_vxlan(skb, &proto, &nhoff);
    if (flag_vxlan == -1) {
        return SR_DROP;
    }

    skb->cb[0] = nhoff;
    switch (proto) {
        case ETH_P_IP:
            ret = ipv4_hash(skb);
            break;
        case ETH_P_IPV6:
            ret = ipv6_hash(skb);
            break;
        default:
            break;
    }

#ifdef DEBUG
    char fmt4[] = "[LB] 4: ret=%u\n";
    bpf_trace_printk(fmt4, sizeof(fmt4), ret);
#endif

    return ret;
}

char __license[] __section("license") = "GPL";

/* libbpf needs version section to check sync of eBPF code and kernel
 * but socket filter don't need it */
__u32 __version __section("version") = LINUX_VERSION_CODE;
