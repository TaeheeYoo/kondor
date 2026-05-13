/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PCKT_ENCAP_H
#define __PCKT_ENCAP_H

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <string.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "balancer_consts.h"
#include "balancer_structs.h"
#include "csum_helpers.h"

__attribute__((__always_inline__))
static inline __u32 create_encap_ipv4_src(__u16 port, __be32 src)
{
	__u32 ip_suffix = bpf_htons(port);

	ip_suffix <<= 16;
	ip_suffix ^= src;
	return ((0xFFFF0000 & ip_suffix) | IPIP_V4_PREFIX);
}

__attribute__((__always_inline__))
static inline void create_v4_hdr(struct iphdr *iph, __u8 tos,
				 __u32 saddr, __u32 daddr,
				 __u16 pkt_bytes, __u8 proto)
{
	__u64 csum = 0;

	iph->version = 4;
	iph->ihl = 5;
	iph->frag_off = 0;
	iph->protocol = proto;
	iph->check = 0;
	iph->tos = tos;
	iph->tot_len = bpf_htons(pkt_bytes + sizeof(struct iphdr));
	iph->id = 0;
	iph->daddr = daddr;
	iph->saddr = saddr;
	iph->ttl = DEFAULT_TTL;
	ipv4_csum_inline(iph, &csum);
	iph->check = csum;
}

__attribute__((__always_inline__))
static inline bool encap_v4(struct xdp_md *xdp, struct ctl_value *cval,
			    struct packet_description *pckt,
			    struct real_definition *dst, __u32 pkt_bytes)
{
	struct ethhdr *new_eth;
	struct ethhdr *old_eth;
	struct iphdr *iph;
	void *data_end;
	void *data;
	__u32 ip_src;

	ip_src = create_encap_ipv4_src(pckt->flow.port16[0], pckt->flow.src);

	if (bpf_xdp_adjust_head(xdp, 0 - (int)sizeof(struct iphdr)))
		return false;

	data = (void *)(long)xdp->data;
	data_end = (void *)(long)xdp->data_end;
	new_eth = data;
	iph = data + sizeof(struct ethhdr);
	old_eth = data + sizeof(struct iphdr);

	if ((void *)(new_eth + 1) > data_end ||
	    (void *)(old_eth + 1) > data_end ||
	    (void *)(iph + 1) > data_end)
		return false;

	memcpy(new_eth->h_dest, cval->mac, 6);
	memcpy(new_eth->h_source, old_eth->h_dest, 6);
	new_eth->h_proto = BE_ETH_P_IP;

	create_v4_hdr(iph, pckt->tos, ip_src, dst->dst,
		      pkt_bytes, IPPROTO_IPIP);
	return true;
}

#endif /* __PCKT_ENCAP_H */
