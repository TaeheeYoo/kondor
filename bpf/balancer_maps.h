/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BALANCER_MAPS_H
#define __BALANCER_MAPS_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "balancer_consts.h"
#include "balancer_structs.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_VIPS);
	__type(key, struct vip_definition);
	__type(value, struct vip_meta);
} vip_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, DEFAULT_LRU_SIZE);
	__type(key, struct flow_key);
	__type(value, struct real_pos_lru);
} lru_cache_inner SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, MAX_SUPPORTED_CPUS);
	__type(key, __u32);
	__array(values, struct {
		__uint(type, BPF_MAP_TYPE_LRU_HASH);
		__uint(max_entries, DEFAULT_LRU_SIZE);
		__type(key, struct flow_key);
		__type(value, struct real_pos_lru);
	});
} lru_mapping SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, DEFAULT_LRU_SIZE);
	__type(key, struct flow_key);
	__type(value, struct real_pos_lru);
} fallback_cache SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, CH_RINGS_SIZE);
	__type(key, __u32);
	__type(value, __u32);
} ch_rings SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_REALS);
	__type(key, __u32);
	__type(value, struct real_definition);
} reals SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_REALS);
	__type(key, __u32);
	__type(value, struct lb_stats);
} reals_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, STATS_MAP_SIZE);
	__type(key, __u32);
	__type(value, struct lb_stats);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, CTL_MAP_SIZE);
	__type(key, __u32);
	__type(value, struct ctl_value);
} ctl_array SEC(".maps");

#endif /* __BALANCER_MAPS_H */
