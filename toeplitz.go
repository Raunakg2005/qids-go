package qids

import (
	"encoding/binary"
	"math/bits"
)

// ReverseBitsTable maps an 8-bit byte to its bit-reversed value.
var ReverseBitsTable [256]byte

func init() {
	for i := 0; i < 256; i++ {
		ReverseBitsTable[i] = bits.Reverse8(byte(i))
	}
}

// ReverseByteBits reverses the bits within each byte of the given data.
func ReverseByteBits(data []byte) []byte {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = ReverseBitsTable[b]
	}
	return out
}

// Clmul64 performs carry-less multiplication of two 64-bit polynomials over GF(2).
// Returns the 128-bit product as (hi, lo).
func Clmul64(a, b uint64) (hi, lo uint64) {
	for i := 0; i < 64; i++ {
		if (b & (1 << i)) != 0 {
			// Add a shifted by i
			lo ^= a << i
			if i > 0 {
				hi ^= a >> (64 - i)
			}
		}
	}
	return hi, lo
}

// PolyMod64 reduces a 128-bit polynomial (vHi, vLo) modulo a degree-64 polynomial p (pHi, pLo) over GF(2).
// p must have bit 64 set (pHi = 1).
func PolyMod64(vHi, vLo uint64, pLo uint64) uint64 {
	// While v >= 2^64 (i.e., vHi != 0)
	for vHi != 0 {
		lz := bits.LeadingZeros64(vHi)
		deg := 127 - lz
		shift := deg - 64

		// XOR with p << shift
		if shift >= 64 {
			s := shift - 64
			vHi ^= (1 << s)
		} else if shift == 0 {
			vHi ^= 1
			vLo ^= pLo
		} else {
			// Shift spans across hi and lo
			vHi ^= (1 << shift) | (pLo >> (64 - shift))
			vLo ^= pLo << shift
		}
	}
	return vLo
}

// GfMul64 multiplies two 64-bit polynomials in GF(2^64) modulo p.
func GfMul64(a, b uint64, pLo uint64) uint64 {
	hi, lo := Clmul64(a, b)
	return PolyMod64(hi, lo, pLo)
}

// MessageChunks64 splits data into 64-bit blocks with injectivity terminator 0x01.
func MessageChunks64(data []byte) []uint64 {
	buf := ReverseByteBits(data)
	buf = append(buf, 0x01) // Injectivity terminator

	for len(buf)%8 != 0 {
		buf = append(buf, 0x00)
	}

	chunks := make([]uint64, len(buf)/8)
	for i := 0; i < len(buf); i += 8 {
		chunks[i/8] = binary.LittleEndian.Uint64(buf[i : i+8])
	}
	return chunks
}

// ToeplitzHash64 computes the 64-bit Toeplitz LFSR universal hash.
// polyLo represents the lower 64 bits of the degree-64 irreducible polynomial (x^64 + polyLo).
func ToeplitzHash64(data []byte, polyLo uint64, seed uint64) uint64 {
	chunks := MessageChunks64(data)
	xN := polyLo // x^64 mod p = polyLo

	var acc uint64
	for i := len(chunks) - 1; i >= 0; i-- {
		acc = GfMul64(acc, xN, polyLo) ^ chunks[i]
	}
	return GfMul64(acc, seed, polyLo)
}
