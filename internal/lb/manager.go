// SPDX-License-Identifier: GPL-2.0
package lb

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/ebpf/link"

	"github.com/patchwork-systems/kondor/internal/model"
)

type vipState struct {
	config model.VIPConfig
	vipNum uint32
	reals  map[string]uint32 // real IP -> index in reals map
}

type Manager struct {
	mu         sync.RWMutex
	objs       *balancerObjects
	xdpLink    link.Link
	ifName     string
	offload    bool
	vips       map[string]*vipState // "ip:port/proto" -> state
	nextVipNum uint32
	nextReal   uint32
	realPool   []uint32 // freed real indices
}

// The protocol arrives as whatever the caller typed, so it is folded here -
// otherwise "udp" and "UDP" name two different VIPs and only one of them is
// ever found again.
func vipKey(vip model.VIP) string {
	return fmt.Sprintf("%s:%d/%s", vip.Address, vip.Port,
		strings.ToLower(vip.Protocol))
}

func ip4ToU32(ip net.IP) uint32 {
	b := ip.To4()
	return binary.NativeEndian.Uint32(b)
}

func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}

/* Zero for anything else, which no packet carries, so a VIP added with a
 * protocol this does not know would sit in the map and never match.  Callers
 * check.
 */
func protoNum(proto string) uint8 {
	switch strings.ToLower(proto) {
	case "tcp":
		return 6
	case "udp":
		return 17
	default:
		return 0
	}
}

func NewManager() *Manager {
	return &Manager{
		vips:     make(map[string]*vipState),
		nextReal: 1,
	}
}

func (m *Manager) Attach(ifName string, offload bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return fmt.Errorf("interface %s: %w", ifName, err)
	}

	if offload {
		return m.attachOffload(ifName, iface.Index)
	}

	spec, err := loadBalancer()
	if err != nil {
		return fmt.Errorf("load BPF: %w", err)
	}

	objs := &balancerObjects{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		return fmt.Errorf("load objects: %w", err)
	}
	m.objs = objs

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.BalancerIngress,
		Interface: iface.Index,
	})
	if err != nil {
		objs.Close()
		return fmt.Errorf("attach XDP: %w", err)
	}

	m.xdpLink = l
	m.ifName = ifName
	return nil
}

func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.xdpLink != nil {
		m.xdpLink.Close()
	}
	if m.objs != nil {
		m.objs.Close()
	}
	if m.offload {
		cleanupPins()
	}
	return nil
}

func (m *Manager) SetRouterMAC(mac net.HardwareAddr) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	val := balancerCtlValue{}
	var buf [8]byte
	copy(buf[:6], mac)
	val.Value = binary.NativeEndian.Uint64(buf[:])

	return m.objs.CtlArray.Put(uint32(0), &val)
}

func (m *Manager) allocReal() uint32 {
	if len(m.realPool) > 0 {
		idx := m.realPool[len(m.realPool)-1]
		m.realPool = m.realPool[:len(m.realPool)-1]
		return idx
	}
	idx := m.nextReal
	m.nextReal++
	return idx
}

func (m *Manager) freeReal(idx uint32) {
	m.realPool = append(m.realPool, idx)
}

func (m *Manager) AddVIP(cfg model.VIPConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := vipKey(cfg.VIP)
	if _, exists := m.vips[key]; exists {
		return fmt.Errorf("VIP %s already exists", key)
	}

	vipNum := m.nextVipNum
	m.nextVipNum++

	mapKey := balancerVipDefinition{}
	mapKey.Vip = ip4ToU32(cfg.VIP.Address)
	mapKey.Port = htons(cfg.VIP.Port)
	mapKey.Proto = protoNum(cfg.VIP.Protocol)
	if mapKey.Proto == 0 {
		return fmt.Errorf("unknown protocol %q, expected tcp or udp",
			cfg.VIP.Protocol)
	}

	mapVal := balancerVipMeta{
		Flags:  cfg.Flags,
		VipNum: vipNum,
	}

	if err := m.objs.VipMap.Put(&mapKey, &mapVal); err != nil {
		return fmt.Errorf("vip_map put: %w", err)
	}

	state := &vipState{
		config: cfg,
		vipNum: vipNum,
		reals:  make(map[string]uint32),
	}

	realIndices := make([]uint32, 0, len(cfg.Reals))
	for _, r := range cfg.Reals {
		idx := m.allocReal()
		rd := balancerRealDefinition{}
		rd.Dst = ip4ToU32(r.Address)

		if err := m.objs.Reals.Put(idx, &rd); err != nil {
			return fmt.Errorf("reals put: %w", err)
		}

		state.reals[r.Address.String()] = idx
		realIndices = append(realIndices, idx)
	}

	m.vips[key] = state

	return m.updateCHRing(state, realIndices)
}

func (m *Manager) DeleteVIP(vip model.VIP) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := vipKey(vip)
	state, exists := m.vips[key]
	if !exists {
		return fmt.Errorf("VIP %s not found", key)
	}

	mapKey := balancerVipDefinition{}
	mapKey.Vip = ip4ToU32(vip.Address)
	mapKey.Port = htons(vip.Port)
	mapKey.Proto = protoNum(vip.Protocol)

	m.objs.VipMap.Delete(&mapKey)

	for _, idx := range state.reals {
		m.freeReal(idx)
	}

	delete(m.vips, key)
	return nil
}

func (m *Manager) AddReal(vip model.VIP, real model.Real) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := vipKey(vip)
	state, exists := m.vips[key]
	if !exists {
		return fmt.Errorf("VIP %s not found", key)
	}

	rKey := real.Address.String()
	if _, exists := state.reals[rKey]; exists {
		return fmt.Errorf("real %s already exists", rKey)
	}

	idx := m.allocReal()
	rd := balancerRealDefinition{}
	rd.Dst = ip4ToU32(real.Address)

	if err := m.objs.Reals.Put(idx, &rd); err != nil {
		m.freeReal(idx)
		return fmt.Errorf("reals put: %w", err)
	}

	state.reals[rKey] = idx
	state.config.Reals = append(state.config.Reals, real)

	indices := make([]uint32, 0, len(state.reals))
	for _, i := range state.reals {
		indices = append(indices, i)
	}

	return m.updateCHRing(state, indices)
}

func (m *Manager) DeleteReal(vip model.VIP, realAddr net.IP) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := vipKey(vip)
	state, exists := m.vips[key]
	if !exists {
		return fmt.Errorf("VIP %s not found", key)
	}

	rKey := realAddr.String()
	idx, exists := state.reals[rKey]
	if !exists {
		return fmt.Errorf("real %s not found", rKey)
	}

	delete(state.reals, rKey)
	m.freeReal(idx)

	newReals := make([]model.Real, 0, len(state.config.Reals)-1)
	for _, r := range state.config.Reals {
		if !r.Address.Equal(realAddr) {
			newReals = append(newReals, r)
		}
	}
	state.config.Reals = newReals

	indices := make([]uint32, 0, len(state.reals))
	for _, i := range state.reals {
		indices = append(indices, i)
	}

	return m.updateCHRing(state, indices)
}

func (m *Manager) updateCHRing(state *vipState, realIndices []uint32) error {
	table := generateMaglevTable(realIndices, len(realIndices))
	base := ringSize * state.vipNum

	for i := 0; i < ringSize; i++ {
		key := base + uint32(i)
		if err := m.objs.ChRings.Put(key, table[i]); err != nil {
			return fmt.Errorf("ch_rings put: %w", err)
		}
	}
	return nil
}

func (m *Manager) ListVIPs() []model.VIPConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]model.VIPConfig, 0, len(m.vips))
	for _, state := range m.vips {
		result = append(result, state.config)
	}
	return result
}

func (m *Manager) GetStats(vip model.VIP) (*model.StatsEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := vipKey(vip)
	state, exists := m.vips[key]
	if !exists {
		// Say what was asked for and what there was, because the two
		// differing by a character is the usual reason to be here.
		known := make([]string, 0, len(m.vips))
		for k := range m.vips {
			known = append(known, k)
		}
		sort.Strings(known)
		if len(known) == 0 {
			return nil, fmt.Errorf("VIP %s not found; none are configured", key)
		}
		return nil, fmt.Errorf("VIP %s not found; configured: %s",
			key, strings.Join(known, ", "))
	}

	// stats is a PERCPU_ARRAY: sum the per-CPU (per-GPU-instance) values.
	var perCPU []balancerLbStats
	if err := m.objs.Stats.Lookup(state.vipNum, &perCPU); err != nil {
		return nil, err
	}

	var packets, bytes uint64
	for i := range perCPU {
		packets += perCPU[i].V1
		bytes += perCPU[i].V2
	}
	return &model.StatsEntry{
		Packets: packets,
		Bytes:   bytes,
	}, nil
}

func protoName(proto uint8) string {
	switch proto {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return fmt.Sprintf("%d", proto)
	}
}

// The address a real index stands for, or the index itself when it stands for
// nothing - a connection table entry outlives the real it was pinned to.
func (m *Manager) realName(pos uint32) string {
	var rd balancerRealDefinition

	if err := m.objs.Reals.Lookup(&pos, &rd); err != nil || rd.Dst == 0 {
		return fmt.Sprintf("#%d", pos)
	}

	addr := make([]byte, 4)
	binary.NativeEndian.PutUint32(addr, rd.Dst)

	return net.IP(addr).String()
}

/* The key is read as bytes rather than through the generated struct.  The
 * ports sit in a union there, which is awkward to name from Go, and both the
 * addresses and the ports are already in the order they are printed in.
 */
func flowFromKey(key []byte, atime uint64, name string) model.ConnCacheEntry {
	srcPort := strconv.Itoa(int(binary.BigEndian.Uint16(key[8:10])))
	dstPort := strconv.Itoa(int(binary.BigEndian.Uint16(key[10:12])))

	return model.ConnCacheEntry{
		Src:   net.JoinHostPort(net.IP(key[0:4]).String(), srcPort),
		Dst:   net.JoinHostPort(net.IP(key[4:8]).String(), dstPort),
		Proto: protoName(key[12]),
		Real:  name,
		Atime: atime,
	}
}

// A flow only stays in the connection table while it is being used, so what is
// in there says as much about the traffic as about the table.  A count far
// below the number of flows offered means entries are not landing; the spread
// in atime says whether they are being aged out instead.
//
// limit caps how many flows are listed; zero lists all of them.  The counts
// cover the whole table either way.
func (m *Manager) ConnCacheInfo(limit int) (*model.ConnCacheInfo, error) {
	var val balancerRealPosLru
	var oldest, newest uint64

	m.mu.RLock()
	defer m.mu.RUnlock()

	info := &model.ConnCacheInfo{
		Capacity: m.objs.ConnCache.MaxEntries(),
		ByReal:   make(map[string]int),
	}

	key := make([]byte, m.objs.ConnCache.KeySize())
	names := make(map[uint32]string)

	it := m.objs.ConnCache.Iterate()
	for it.Next(&key, &val) {
		if info.Entries == 0 || val.Atime < oldest {
			oldest = val.Atime
		}
		if val.Atime > newest {
			newest = val.Atime
		}
		info.Entries++

		name, seen := names[val.Pos]
		if !seen {
			name = m.realName(val.Pos)
			names[val.Pos] = name
		}
		info.ByReal[name]++

		if len(key) < 13 {
			continue
		}
		if limit > 0 && len(info.Flows) >= limit {
			info.Truncated = true
			continue
		}
		info.Flows = append(info.Flows, flowFromKey(key, val.Atime, name))
	}
	if err := it.Err(); err != nil {
		return nil, err
	}

	/* atime comes from the GPU's snapshot of ktime, so the spread between
	 * the two ends is reported rather than an age against a host clock that
	 * reads differently.
	 */
	info.Spread = newest - oldest

	return info, nil
}

func (m *Manager) GetGlobalStats() map[string]model.StatsEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]model.StatsEntry)
	names := map[int]string{
		16: "total", 17: "tx", 18: "drop", 19: "pass",
		1: "lru_miss", 7: "encap_fail",
	}

	for offset, name := range names {
		key := uint32(512 + offset)
		var perCPU []balancerLbStats
		if err := m.objs.Stats.Lookup(key, &perCPU); err != nil {
			continue
		}
		// Only the total counter carries bytes; the rest are counted
		// after the head may have moved, where the length is no longer
		// there to read.
		var e model.StatsEntry
		for i := range perCPU {
			e.Packets += perCPU[i].V1
			e.Bytes += perCPU[i].V2
		}
		result[name] = e
	}
	return result
}
