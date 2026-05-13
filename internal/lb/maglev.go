// SPDX-License-Identifier: GPL-2.0
package lb

import (
	"encoding/binary"
	"hash/crc32"
)

const ringSize = 65537

func generateMaglevTable(reals []uint32, numReals int) []uint32 {
	table := make([]uint32, ringSize)
	if numReals == 0 {
		return table
	}

	type perm struct {
		offset uint64
		skip   uint64
	}
	perms := make([]perm, numReals)

	for i := 0; i < numReals; i++ {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, reals[i])
		h1 := uint64(crc32.ChecksumIEEE(b))
		h2 := uint64(crc32.Update(0xffffffff, crc32.MakeTable(crc32.Castagnoli), b))
		perms[i] = perm{
			offset: h1 % ringSize,
			skip:   (h2 % (ringSize - 1)) + 1,
		}
	}

	next := make([]uint64, numReals)
	entry := make([]int, ringSize)
	for i := range entry {
		entry[i] = -1
	}

	filled := 0
	for filled < ringSize {
		for i := 0; i < numReals; i++ {
			c := (perms[i].offset + next[i]*perms[i].skip) % ringSize
			for entry[c] != -1 {
				next[i]++
				c = (perms[i].offset + next[i]*perms[i].skip) % ringSize
			}
			entry[c] = i
			next[i]++
			filled++
			if filled == ringSize {
				break
			}
		}
	}

	for i := 0; i < ringSize; i++ {
		table[i] = reals[entry[i]]
	}

	return table
}
