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
