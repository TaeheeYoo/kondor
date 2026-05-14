// SPDX-License-Identifier: GPL-2.0
package lb

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:embed balancer_bpfel.o
var bpfELFBytes []byte

const pinBase = "/sys/fs/bpf/kondor"

func (m *Manager) attachOffload(ifName string, ifIndex int) error {
	tmp, err := os.CreateTemp("", "kondor-bpf-*.o")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := tmp.Write(bpfELFBytes); err != nil {
		tmp.Close()
		return fmt.Errorf("write BPF object: %w", err)
	}
	tmp.Close()

	os.MkdirAll(pinBase, 0700)

	out, err := exec.Command("bpftool", "prog", "loadall",
		tmpPath, pinBase, "pinmaps", pinBase, "dev", ifName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("bpftool loadall: %s: %w", string(out), err)
	}

	objs := &balancerObjects{}

	objs.BalancerIngress, err = ebpf.LoadPinnedProgram(
		filepath.Join(pinBase, "balancer_ingress"), nil)
	if err != nil {
		cleanupPins()
		return fmt.Errorf("open pinned prog: %w", err)
	}

	type mapEntry struct {
		name string
		dest **ebpf.Map
	}
	maps := []mapEntry{
		{"vip_map", &objs.VipMap},
		{"ch_rings", &objs.ChRings},
		{"reals", &objs.Reals},
		{"reals_stats", &objs.RealsStats},
		{"stats", &objs.Stats},
		{"ctl_array", &objs.CtlArray},
		{"conn_cache", &objs.ConnCache},
	}
	for _, me := range maps {
		*me.dest, err = ebpf.LoadPinnedMap(
			filepath.Join(pinBase, me.name), nil)
		if err != nil {
			cleanupPins()
			return fmt.Errorf("open pinned map %s: %w", me.name, err)
		}
	}

	m.objs = objs

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.BalancerIngress,
		Interface: ifIndex,
		Flags:     link.XDPOffloadMode,
	})
	if err != nil {
		cleanupPins()
		objs.Close()
		return fmt.Errorf("attach XDP: %w", err)
	}

	m.xdpLink = l
	m.ifName = ifName
	m.offload = true
	return nil
}

func cleanupPins() {
	entries, err := os.ReadDir(pinBase)
	if err != nil {
		return
	}
	for _, e := range entries {
		os.Remove(filepath.Join(pinBase, e.Name()))
	}
	os.Remove(pinBase)
}
