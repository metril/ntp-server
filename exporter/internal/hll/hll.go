// Package hll is an exact port of the Python HyperLogLog class in
// exporter.py: same precision, same hash function (SHA-1 truncated to the
// first 8 bytes, big-endian), same estimator/bias correction, same merge
// semantics, so ntp_clients_unique_daily stays bit-identical across the
// rewrite.
package hll

import (
	"crypto/sha1"
	"math"
	"math/bits"
)

// HyperLogLog is a fixed-precision HyperLogLog over SHA-1-hashed string
// keys. p=14 gives m=16384 one-byte registers (16 KiB) and ~0.81% standard
// error. Only the small-range linear-counting correction is applied; with a
// 64-bit hash the large-range correction is unnecessary.
type HyperLogLog struct {
	p         uint
	m         int
	alpha     float64
	bits      uint
	registers []byte
}

// New creates a HyperLogLog with precision p (4 <= p <= 16). Panics outside
// that range, mirroring the Python ValueError.
func New(p uint) *HyperLogLog {
	if p < 4 || p > 16 {
		panic("p must be between 4 and 16")
	}
	m := 1 << p
	return &HyperLogLog{
		p:         p,
		m:         m,
		alpha:     0.7213 / (1.0 + 1.079/float64(m)),
		bits:      64 - p,
		registers: make([]byte, m),
	}
}

// NewDefault creates a HyperLogLog with p=14, matching HyperLogLog() in
// exporter.py.
func NewDefault() *HyperLogLog {
	return New(14)
}

// Add hashes key with SHA-1 and updates the register it maps to.
func (h *HyperLogLog) Add(key string) {
	sum := sha1.Sum([]byte(key))
	var v uint64
	for i := 0; i < 8; i++ {
		v = v<<8 | uint64(sum[i])
	}
	idx := v >> h.bits
	w := v & ((uint64(1) << h.bits) - 1)
	var rho uint
	if w == 0 {
		rho = h.bits + 1
	} else {
		// Python: bits - w.bit_length() + 1. bits.Len64 is equivalent to
		// Python's int.bit_length() for a positive value.
		rho = h.bits - uint(bits.Len64(w)) + 1
	}
	if byte(rho) > h.registers[idx] {
		h.registers[idx] = byte(rho)
	}
}

// Merge takes the register-wise max of other into h. Panics if precisions
// differ, mirroring the Python ValueError.
func (h *HyperLogLog) Merge(other *HyperLogLog) {
	if other.p != h.p {
		panic("cannot merge HyperLogLog sketches of different precision")
	}
	for i := range h.registers {
		if other.registers[i] > h.registers[i] {
			h.registers[i] = other.registers[i]
		}
	}
}

// Count returns the cardinality estimate.
func (h *HyperLogLog) Count() float64 {
	raw := 0.0
	zeros := 0
	for _, r := range h.registers {
		raw += 1.0 / float64(uint64(1)<<r)
		if r == 0 {
			zeros++
		}
	}
	m := float64(h.m)
	estimate := h.alpha * m * m / raw
	if estimate <= 2.5*m && zeros > 0 {
		return m * math.Log(m/float64(zeros))
	}
	return estimate
}

// Clone returns an independent copy of h, safe to read/merge without
// synchronizing with concurrent Add() calls on the original.
func (h *HyperLogLog) Clone() *HyperLogLog {
	registers := make([]byte, len(h.registers))
	copy(registers, h.registers)
	return &HyperLogLog{
		p:         h.p,
		m:         h.m,
		alpha:     h.alpha,
		bits:      h.bits,
		registers: registers,
	}
}
