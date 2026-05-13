// SPDX-License-Identifier: GPL-2.0
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <stddef.h>

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "balancer_consts.h"
#include "balancer_structs.h"
#include "balancer_maps.h"
#include "pckt_parsing.h"
#include "pckt_encap.h"
#include "jhash.h"

__attribute__((__always_inline__))
static inline void increment_stats(int offset, struct lb_stats *delta)
{
	__u32 key = MAX_VIPS + offset;
	struct lb_stats *counters;

	counters = bpf_map_lookup_elem(&stats, &key);
	if (!counters)
		return;
	__sync_fetch_and_add(&counters->v1, delta->v1);
	__sync_fetch_and_add(&counters->v2, delta->v2);
}

__attribute__((__always_inline__))
static inline __u32 get_packet_hash(struct packet_description *pckt)
{
	return jhash_2words(pckt->flow.src, pckt->flow.ports, INIT_JHASH_SEED);
}

__attribute__((__always_inline__))
static inline bool connection_table_lookup(struct real_pos_lru **dst,
					   struct packet_description *pckt,
					   __u32 cpu_num, bool is_syn)
{
	struct real_pos_lru *pos_lru;
	void *lru_map;
	__u64 cur_time;

	if (is_syn)
		return false;

	lru_map = bpf_map_lookup_elem(&lru_mapping, &cpu_num);
	if (!lru_map)
		return false;

	pos_lru = bpf_map_lookup_elem(lru_map, &pckt->flow);
	if (!pos_lru)
		return false;

	if (pckt->flow.proto == IPPROTO_UDP) {
		cur_time = bpf_ktime_get_ns();
		if (cur_time - pos_lru->atime > LRU_UDP_TIMEOUT)
			return false;
		pos_lru->atime = cur_time;
	}

	*dst = pos_lru;
	return true;
}

__attribute__((__always_inline__))
static inline void connection_table_insert(struct packet_description *pckt,
					   __u32 cpu_num, __u32 pos)
{
	struct real_pos_lru new_entry = {};
	void *lru_map;

	new_entry.pos = pos;
	new_entry.atime = bpf_ktime_get_ns();

	lru_map = bpf_map_lookup_elem(&lru_mapping, &cpu_num);
	if (!lru_map)
		return;

	bpf_map_update_elem(lru_map, &pckt->flow, &new_entry, BPF_ANY);
}

__attribute__((__always_inline__))
static inline int get_packet_dst(struct real_definition **real,
				 struct packet_description *pckt,
				 struct vip_meta *vip_info,
				 __u32 cpu_num, bool is_syn)
{
	struct lb_stats *conn_rate;
	struct real_pos_lru *dst_lru;
	struct lb_stats lru_delta = {};
	__u32 hash, key, *real_pos;

	if (!(vip_info->flags & F_LRU_BYPASS) &&
	    connection_table_lookup(&dst_lru, pckt, cpu_num, is_syn)) {
		*real = bpf_map_lookup_elem(&reals, &dst_lru->pos);
		if (*real)
			return 0;
	}

	lru_delta.v1 += 1;
	increment_stats(LRU_MISS_CNTR, &lru_delta);

	hash = get_packet_hash(pckt) % RING_SIZE;
	key = RING_SIZE * vip_info->vip_num + hash;

	real_pos = bpf_map_lookup_elem(&ch_rings, &key);
	if (!real_pos)
		return -1;

	key = *real_pos;
	pckt->real_index = key;
	*real = bpf_map_lookup_elem(&reals, &key);
	if (!*real)
		return -1;

	if (!(vip_info->flags & F_LRU_BYPASS) && !is_syn) {
		conn_rate = bpf_map_lookup_elem(&stats,
						&((__u32){ MAX_VIPS + NEW_CONN_RATE_CNTR }));
		if (conn_rate && conn_rate->v1 < MAX_CONN_RATE) {
			__sync_fetch_and_add(&conn_rate->v1, 1);
			connection_table_insert(pckt, cpu_num, *real_pos);
		}
	}

	return 0;
}

__attribute__((__always_inline__))
static inline int process_packet(void *data, __u64 pkt_off,
				 void *data_end, struct xdp_md *xdp)
{
	struct packet_description pckt = {};
	struct real_definition *dst = NULL;
	struct lb_stats pkt_delta = {};
	struct vip_definition vip = {};
	struct lb_stats *per_real;
	struct lb_stats *per_vip;
	struct vip_meta *vip_info;
	struct ctl_value *cval;
	__u16 pkt_bytes = 0;
	__u8 protocol = 0;
	__u32 vip_num;
	bool is_syn;
	int ret;

	ret = parse_l3_headers(&pckt, &protocol, &pkt_bytes, data, data_end);
	if (ret != FURTHER_PROCESSING)
		return ret;

	if (protocol == IPPROTO_TCP) {
		if (!parse_tcp(data, data_end, &pckt))
			return XDP_DROP;
	} else if (protocol == IPPROTO_UDP) {
		if (!parse_udp(data, data_end, &pckt))
			return XDP_DROP;
	} else {
		return XDP_PASS;
	}

	vip.vip = pckt.flow.dst;
	vip.port = pckt.flow.port16[1];
	vip.proto = pckt.flow.proto;

	vip_info = bpf_map_lookup_elem(&vip_map, &vip);
	if (!vip_info) {
		vip.port = 0;
		vip_info = bpf_map_lookup_elem(&vip_map, &vip);
		if (!vip_info)
			return XDP_PASS;
	}

	pkt_delta.v1 += 1;
	pkt_delta.v2 += pkt_bytes;
	vip_num = vip_info->vip_num;
	per_vip = bpf_map_lookup_elem(&stats, &vip_num);
	if (per_vip) {
		__sync_fetch_and_add(&per_vip->v1, pkt_delta.v1);
		__sync_fetch_and_add(&per_vip->v2, pkt_delta.v2);
	}

	if (vip_info->flags & F_HASH_NO_SRC_PORT)
		pckt.flow.port16[0] = 0;

	if (vip_info->flags & F_HASH_DPORT_ONLY) {
		pckt.flow.port16[0] = pckt.flow.port16[1];
		pckt.flow.src = 0;
	}

	is_syn = pckt.flags & F_SYN_SET;

	if (get_packet_dst(&dst, &pckt, vip_info, 0, is_syn))
		return XDP_DROP;
	if (!dst)
		return XDP_DROP;

	per_real = bpf_map_lookup_elem(&reals_stats, &pckt.real_index);
	if (per_real) {
		__sync_fetch_and_add(&per_real->v1, 1);
		__sync_fetch_and_add(&per_real->v2, pkt_bytes);
	}

	cval = bpf_map_lookup_elem(&ctl_array,
				   &((__u32){ CTL_MAC_INDEX }));
	if (!cval)
		return XDP_DROP;

	if (!encap_v4(xdp, cval, &pckt, dst, pkt_bytes)) {
		struct lb_stats encap_delta = { .v1 = 1 };

		increment_stats(ENCAP_FAIL_CNTR, &encap_delta);
		return XDP_DROP;
	}

	return XDP_TX;
}

SEC("xdp")
int balancer_ingress(struct xdp_md *ctx)
{
	struct lb_stats total_delta = {};
	struct lb_stats act_delta = {};
	struct ethhdr *eth;
	void *data_end;
	void *data;
	int action;

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_DROP;
	if (eth->h_proto != BE_ETH_P_IP)
		return XDP_PASS;

	total_delta.v1 += 1;
	increment_stats(XDP_TOTAL_CNTR, &total_delta);

	action = process_packet(data, sizeof(struct ethhdr), data_end, ctx);

	act_delta.v1 += 1;
	if (action == XDP_TX)
		increment_stats(XDP_TX_CNTR, &act_delta);
	else if (action == XDP_DROP)
		increment_stats(XDP_DROP_CNTR, &act_delta);
	else
		increment_stats(XDP_PASS_CNTR, &act_delta);

	return action;
}

char _license[] SEC("license") = "GPL";
