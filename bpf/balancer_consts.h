/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BALANCER_CONSTS_H
#define __BALANCER_CONSTS_H

#define BE_ETH_P_IP   8       /* htons(ETH_P_IP) */
#define BE_ETH_P_IPV6 56710   /* htons(ETH_P_IPV6) */

#define FURTHER_PROCESSING  (-1)
#define PCKT_FRAGMENTED     65343  /* htons(IP_MF | IP_OFFSET) */

#define IPV4_HDR_LEN_NO_OPT 20

#define RING_SIZE            65537
#define MAX_VIPS             512
#define MAX_REALS            4096
#define CTL_MAP_SIZE         16
#define CH_RINGS_SIZE        (MAX_VIPS * RING_SIZE)
#define STATS_MAP_SIZE       (MAX_VIPS * 2)
#define MAX_SUPPORTED_CPUS   128
#define DEFAULT_LRU_SIZE     1000000

#define ONE_SEC              1000000000ULL  /* 1s in nanoseconds */
#define LRU_UDP_TIMEOUT      (30 * ONE_SEC)

/* VIP flags */
#define F_HASH_NO_SRC_PORT   (1 << 0)
#define F_LRU_BYPASS         (1 << 1)
#define F_HASH_DPORT_ONLY    (1 << 3)
#define NO_FLAGS             0

/* Packet description flags */
#define F_SYN_SET            (1 << 0)
#define F_RST_SET            (1 << 4)
#define F_ICMP               (1 << 5)

#define DEFAULT_TTL          64
#define IPIP_V4_PREFIX       4268  /* 0x10AC = 172.16 in BE */
#define MAX_PCKT_SIZE        1514

#define INIT_JHASH_SEED      CH_RINGS_SIZE
#define INIT_JHASH_SEED_V6   MAX_VIPS

/* Stats map offsets (stats[MAX_VIPS + X]) */
#define LRU_CNTRS            0
#define LRU_MISS_CNTR        1
#define NEW_CONN_RATE_CNTR   2
#define FALLBACK_LRU_CNTR    3
#define ENCAP_FAIL_CNTR      7
#define CH_DROP_STATS        9
#define XDP_TOTAL_CNTR       16
#define XDP_TX_CNTR          17
#define XDP_DROP_CNTR        18
#define XDP_PASS_CNTR        19

#define MAX_CONN_RATE        125000

#define CTL_MAC_INDEX        0

#define PCKT_ENCAP_V4        encap_v4

#endif /* __BALANCER_CONSTS_H */
