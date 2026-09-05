package qids

import (
	"testing"
)

func TestClmulAndPolyMod(t *testing.T) {
	// (x + 1) * (x + 1) = x^2 + 1
	// 3 * 3 = 0b11 * 0b11 = 0b101 = 5
	hi, lo := Clmul64(3, 3)
	if hi != 0 || lo != 5 {
		t.Fatalf("expected 5, got hi=%d lo=%d", hi, lo)
	}

	// 5 mod (x^3 + x + 1) [0b1011 = 11]
	// Degree 3 polynomial reduction
	pLo := uint64(0b11011) // x^64 + x^4 + x^3 + x + 1
	h := GfMul64(100, 200, pLo)
	if h == 0 {
		t.Fatalf("expected non-zero GF product")
	}
}

func TestToeplitzHashDeterminism(t *testing.T) {
	data := []byte("FINANCIAL_TRANSACTION_PAYLOAD_1000")
	pLo := uint64(0b11011)
	seed := uint64(0xDEADBEEFCAFE1234)

	h1 := ToeplitzHash64(data, pLo, seed)
	h2 := ToeplitzHash64(data, pLo, seed)

	if h1 != h2 {
		t.Fatalf("hash non-deterministic: %d != %d", h1, h2)
	}
	if h1 == 0 {
		t.Fatalf("hash was unexpectedly zero")
	}

	// Distinct payload yields distinct hash
	altData := []byte("FINANCIAL_TRANSACTION_PAYLOAD_1001")
	hAlt := ToeplitzHash64(altData, pLo, seed)
	if h1 == hAlt {
		t.Fatalf("hash collision detected")
	}
}

func TestSPRTThreatDetection(t *testing.T) {
	detector, err := NewSequentialTest(0.02, 0.25, 1e-4, 1e-4)
	if err != nil {
		t.Fatalf("failed to create SPRT: %v", err)
	}

	// Attack stream: 1 error in 4
	attackNoise := []bool{
		true, false, false, false,
		true, false, false, false,
		true, false, false, false,
		true, false, false, false,
		true, false, false, false,
	}

	state := detector.Feed(attackNoise)
	if state != SprtAcceptH1 {
		t.Fatalf("expected ACCEPT_H1, got %v", state)
	}
	if detector.StoppedAt == 0 || detector.StoppedAt > len(attackNoise) {
		t.Fatalf("invalid stopped_at: %d", detector.StoppedAt)
	}

	// Clean stream: honest acceptance
	detector.Reset()
	cleanStream := make([]bool, 40)
	cleanState := detector.Feed(cleanStream)
	if cleanState != SprtAcceptH0 {
		t.Fatalf("expected ACCEPT_H0, got %v", cleanState)
	}
}

func TestETSIKeyBits(t *testing.T) {
	key := ETSIKey{
		KeyID:    "key-1",
		KeyBytes: []byte{0b10101010, 0b11000011},
		SizeBits: 16,
	}

	bits := key.ToBitList()
	if len(bits) != 16 {
		t.Fatalf("expected 16 bits, got %d", len(bits))
	}

	expected := []int{1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1}
	for i, b := range bits {
		if b != expected[i] {
			t.Fatalf("bit %d mismatch: %d != %d", i, b, expected[i])
		}
	}
}
