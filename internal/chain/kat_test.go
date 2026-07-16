// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package chain

import (
	"encoding/hex"
	"testing"
)

// TestComputeKnownAnswer pins Compute to fixed SHA-256 test vectors computed
// out-of-band. This is what kills a mutant that drops h.Write(prev), reorders
// the writes, or skips the sequence: such a mutant produces a different digest
// than the fixed vector, so this test reds even though Author+Verify would
// agree with the mutated code symmetrically.
func TestComputeKnownAnswer(t *testing.T) {
	// Vector 1: genesis prev (32 zero bytes), seq 7, fixed event bytes.
	prev := make([]byte, HashSize)
	got := Compute(prev, 7, []byte("canonical-event-bytes-fixture"))
	want := "9ecfec67a4093919fad7bba159af139cdb5cb06657dbdae13a534692b641ac91"
	if hex.EncodeToString(got) != want {
		t.Fatalf("vector 1: got %s want %s", hex.EncodeToString(got), want)
	}

	// Vector 2: prev = 0x00..0x1f, seq 42, event "x".
	prev2 := make([]byte, HashSize)
	for i := range prev2 {
		prev2[i] = byte(i)
	}
	got2 := Compute(prev2, 42, []byte("x"))
	want2 := "3ed326adde71adb8bc3e5664d33e720cd38e138eb4eb33e01b7c06f090b55977"
	if hex.EncodeToString(got2) != want2 {
		t.Fatalf("vector 2: got %s want %s", hex.EncodeToString(got2), want2)
	}
}

// TestComputeSensitiveToEachInput asserts Compute changes when prev, seq, or
// the event bytes change independently. This kills a mutant that ignores any
// one of the three inputs (e.g. drops the prev or the sequence write).
func TestComputeSensitiveToEachInput(t *testing.T) {
	base := Compute(make([]byte, HashSize), 1, []byte("e"))

	prevChanged := make([]byte, HashSize)
	prevChanged[0] = 1
	if hex.EncodeToString(Compute(prevChanged, 1, []byte("e"))) == hex.EncodeToString(base) {
		t.Fatal("Compute must depend on prev")
	}
	if hex.EncodeToString(Compute(make([]byte, HashSize), 2, []byte("e"))) == hex.EncodeToString(base) {
		t.Fatal("Compute must depend on sequence")
	}
	if hex.EncodeToString(Compute(make([]byte, HashSize), 1, []byte("f"))) == hex.EncodeToString(base) {
		t.Fatal("Compute must depend on the event bytes")
	}
}

// TestAuthorSetsBothHashes asserts Author writes a fresh copied PrevHash and a
// ChainHash equal to Compute over that PrevHash. This pins Author's two writes
// so a mutant that drops either assignment is killed.
func TestAuthorSetsBothHashes(t *testing.T) {
	recs := buildChain("s", 1)
	rec := recs[0]
	if len(rec.PrevHash) != HashSize {
		t.Fatalf("PrevHash length %d, want %d", len(rec.PrevHash), HashSize)
	}
	// Genesis: PrevHash must equal GenesisPrevHash bytes.
	for i, b := range rec.PrevHash {
		if b != 0 {
			t.Fatalf("genesis PrevHash byte %d = %d, want 0", i, b)
		}
	}
	want := Compute(rec.PrevHash, rec.Sequence, rec.CanonicalEventBytes())
	if hex.EncodeToString(rec.ChainHash) != hex.EncodeToString(want) {
		t.Fatal("Author ChainHash must equal Compute over PrevHash")
	}
}
