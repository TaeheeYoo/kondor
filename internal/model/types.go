// SPDX-License-Identifier: GPL-2.0
package model

import "net"

type VIP struct {
	Address  net.IP `json:"address"`
	Port     uint16 `json:"port"`
	Protocol string `json:"protocol"`
}

type Real struct {
	Address net.IP `json:"address"`
	Weight  int    `json:"weight,omitempty"`
}

type VIPConfig struct {
	VIP   VIP    `json:"vip"`
	Reals []Real `json:"reals"`
	Flags uint32 `json:"flags,omitempty"`
}

type StatsEntry struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// One flow held in the connection table, and the real it was pinned to.
type ConnCacheEntry struct {
	Src   string `json:"src"`
	Dst   string `json:"dst"`
	Proto string `json:"proto"`
	Real  string `json:"real"`
	Atime uint64 `json:"atime_ns"`
}

// What the connection table holds right now: how many flows are in it, how
// much room there is, which real each one was pinned to, and how far apart the
// least and most recently used of them were touched.
type ConnCacheInfo struct {
	Entries   int              `json:"entries"`
	Capacity  uint32           `json:"capacity"`
	ByReal    map[string]int   `json:"by_real,omitempty"`
	Spread    uint64           `json:"atime_spread_ns,omitempty"`
	Truncated bool             `json:"truncated,omitempty"`
	Flows     []ConnCacheEntry `json:"flows,omitempty"`
}
