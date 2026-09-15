/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PCKT_ENCAP_H
#define __PCKT_ENCAP_H

#include <linux/if_ether.h>
#include <linux/ip.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "balancer_consts.h"
#include "balancer_structs.h"

__attribute__((__always_inline__))
static inline __u32 create_encap_ipv4_src(__u16 port, __be32 src)
{
	__u32 ip_suffix = bpf_htons(port);

	ip_suffix <<= 16;
	ip_suffix ^= src;
	return ((0xFFFF0000 & ip_suffix) | IPIP_V4_PREFIX);
}

/* One's complement sum of the header's five words; folding the carries is
 * what makes summing 32 bits at a time equal summing the 16-bit words.
 */
__attribute__((__always_inline__))
static inline __u16 ipv4_csum_words(__u32 w0, __u32 w1, __u32 w2,
				    __u32 w3, __u32 w4)
{
	__u64 s = (__u64)w0 + w1 + w2 + w3 + w4;

	s = (s & 0xffffffff) + (s >> 32);
	s = (s & 0xffff) + (s >> 16);
	s = (s & 0xffff) + (s >> 16);
	return ~s;
}

/* The outer headers are built in registers and stored as whole words: data is
 * 2 mod 4 (NET_IP_ALIGN), so offsets 2, 6, 10 and everything from 14 on are
 * dword-aligned.  The old destination is read before the IP header overwrites
 * it.
 */
__attribute__((__always_inline__))
static inline bool encap_v4(struct xdp_md *xdp, struct ctl_value *cval,
			    struct packet_description *pckt,
			    struct real_definition *dst, __u32 pkt_bytes)
{
	__u32 ip_src, w0, w2, src_hi;
	void *data_end;
	__u16 src_lo;
	__u64 mac;
	void *data;

	ip_src = create_encap_ipv4_src(pckt->flow.port16[0], pckt->flow.src);

	if (bpf_xdp_adjust_head(xdp, 0 - (int)sizeof(struct iphdr)))
		return false;

	data = (void *)(long)xdp->data;
	data_end = (void *)(long)xdp->data_end;
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) +
	    sizeof(struct ethhdr) > data_end)
		return false;

	src_lo = *(__u16 *)(data + sizeof(struct iphdr));
	src_hi = *(__u32 *)(data + sizeof(struct iphdr) + 2);
	mac = cval->value;

	*(__u16 *)(data + 0) = mac;
	*(__u32 *)(data + 2) = mac >> 16;
	*(__u32 *)(data + 6) = src_lo | (src_hi << 16);
	*(__u32 *)(data + 10) = (src_hi >> 16) | ((__u32)BE_ETH_P_IP << 16);

	w0 = 0x45 | ((__u32)pckt->tos << 8) |
	     ((__u32)bpf_htons(pkt_bytes + sizeof(struct iphdr)) << 16);
	w2 = DEFAULT_TTL | ((__u32)IPPROTO_IPIP << 8);
	w2 |= (__u32)ipv4_csum_words(w0, 0, w2, ip_src, dst->dst) << 16;

	*(__u32 *)(data + 14) = w0;
	*(__u32 *)(data + 18) = 0;
	*(__u32 *)(data + 22) = w2;
	*(__u32 *)(data + 26) = ip_src;
	*(__u32 *)(data + 30) = dst->dst;
	return true;
}

#endif /* __PCKT_ENCAP_H */
