// SPDX-License-Identifier: GPL-2.0
package lb

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" -type flow_key -type vip_definition -type vip_meta -type real_definition -type real_pos_lru -type lb_stats -type ctl_value balancer ../../bpf/balancer.bpf.c -- -I../../bpf
