/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BALANCER_STRUCTS_H
#define __BALANCER_STRUCTS_H

#include <linux/types.h>

struct flow_key {
	__be32 src;
	__be32 dst;
	union {
		__u32 ports;
		__u16 port16[2];
	};
	__u8 proto;
};

struct packet_description {
	struct flow_key flow;
	__u32 real_index;
	__u8 flags;
	__u8 tos;
};

struct ctl_value {
	union {
		__u64 value;
		__u32 ifindex;
		__u8 mac[6];
	};
};

struct vip_definition {
	__be32 vip;
	__u16 port;
	__u8 proto;
};

struct vip_meta {
	__u32 flags;
	__u32 vip_num;
};

struct real_pos_lru {
	__u32 pos;
	__u64 atime;
};

struct real_definition {
	__be32 dst;
	__u8 flags;
};

struct lb_stats {
	__u64 v1;
	__u64 v2;
};

struct eth_hdr {
	unsigned char eth_dest[6];
	unsigned char eth_source[6];
	unsigned short eth_proto;
};

#endif /* __BALANCER_STRUCTS_H */
