/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PCKT_PARSING_H
#define __PCKT_PARSING_H

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stdbool.h>

#include <bpf/bpf_endian.h>

#include "balancer_consts.h"
#include "balancer_structs.h"

__attribute__((__always_inline__))
static inline bool parse_udp(void *data, void *data_end,
			     struct packet_description *pckt)
{
	__u64 off = sizeof(struct ethhdr) + sizeof(struct iphdr);
	struct udphdr *udp;

	udp = data + off;
	if ((void *)(udp + 1) > data_end)
		return false;

	pckt->flow.port16[0] = udp->source;
	pckt->flow.port16[1] = udp->dest;
	return true;
}

__attribute__((__always_inline__))
static inline bool parse_tcp(void *data, void *data_end,
			     struct packet_description *pckt)
{
	__u64 off = sizeof(struct ethhdr) + sizeof(struct iphdr);
	struct tcphdr *tcp;

	tcp = data + off;
	if ((void *)(tcp + 1) > data_end)
		return false;

	if (tcp->syn)
		pckt->flags |= F_SYN_SET;
	if (tcp->rst)
		pckt->flags |= F_RST_SET;

	pckt->flow.port16[0] = tcp->source;
	pckt->flow.port16[1] = tcp->dest;
	return true;
}

__attribute__((__always_inline__))
static inline int parse_l3_headers(struct packet_description *pckt,
				   __u8 *protocol, __u16 *pkt_bytes,
				   void *data, void *data_end)
{
	struct iphdr *iph;

	iph = data + sizeof(struct ethhdr);
	if ((void *)(iph + 1) > data_end)
		return XDP_DROP;

	if (iph->ihl != 5)
		return XDP_DROP;

	if (iph->frag_off & PCKT_FRAGMENTED)
		return XDP_DROP;

	*protocol = iph->protocol;
	pckt->flow.proto = *protocol;
	pckt->tos = iph->tos;
	*pkt_bytes = bpf_ntohs(iph->tot_len);
	pckt->flow.src = iph->saddr;
	pckt->flow.dst = iph->daddr;

	return FURTHER_PROCESSING;
}

#endif /* __PCKT_PARSING_H */
