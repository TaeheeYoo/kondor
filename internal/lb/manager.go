// SPDX-License-Identifier: GPL-2.0
package lb

import (
	"encoding/binary"
	"fmt"
	"net"
	"runtime"
	"sync"

	"github.com/cilium/ebpf"
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
	vips       map[string]*vipState // "ip:port/proto" -> state
	nextVipNum uint32
	nextReal   uint32
	realPool   []uint32 // freed real indices
}

func vipKey(vip model.VIP) string {
	return fmt.Sprintf("%s:%d/%s", vip.Address, vip.Port, vip.Protocol)
}

func ip4ToU32(ip net.IP) uint32 {
	b := ip.To4()
	return binary.NativeEndian.Uint32(b)
}

func protoNum(proto string) uint8 {
	switch proto {
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

func (m *Manager) Attach(ifName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	spec, err := loadBalancer()
	if err != nil {
		return fmt.Errorf("load BPF: %w", err)
	}

	numCPUs := runtime.NumCPU()
	if numCPUs > 128 {
		numCPUs = 128
	}

	innerSpec := &ebpf.MapSpec{
		Type:       ebpf.LRUHash,
		KeySize:    uint32(binary.Size(balancerFlowKey{})),
		ValueSize:  uint32(binary.Size(balancerRealPosLru{})),
		MaxEntries: 1000000,
	}
	outerSpec := spec.Maps["lru_mapping"]
	outerSpec.MaxEntries = uint32(numCPUs)
	outerSpec.InnerMap = innerSpec

	objs := &balancerObjects{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		return fmt.Errorf("load objects: %w", err)
	}
	m.objs = objs

	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		objs.Close()
		return fmt.Errorf("interface %s: %w", ifName, err)
	}

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
	mapKey.Port = cfg.VIP.Port
	mapKey.Proto = protoNum(cfg.VIP.Protocol)

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
	mapKey.Port = vip.Port
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
		return nil, fmt.Errorf("VIP %s not found", key)
	}

	var values []balancerLbStats
	if err := m.objs.Stats.Lookup(state.vipNum, &values); err != nil {
		return nil, err
	}

	entry := &model.StatsEntry{}
	for _, v := range values {
		entry.Packets += v.V1
		entry.Bytes += v.V2
	}
	return entry, nil
}

func (m *Manager) GetGlobalStats() map[string]uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]uint64)
	names := map[int]string{
		16: "total", 17: "tx", 18: "drop", 19: "pass",
		1: "lru_miss", 7: "encap_fail",
	}

	for offset, name := range names {
		key := uint32(512 + offset)
		var values []balancerLbStats
		if err := m.objs.Stats.Lookup(key, &values); err != nil {
			continue
		}
		var total uint64
		for _, v := range values {
			total += v.V1
		}
		result[name] = total
	}
	return result
}
