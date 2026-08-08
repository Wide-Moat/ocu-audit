// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package merkletree

import (
	"bytes"
	"fmt"
	"testing"
)

// ADR-0045: the retention checkpoint records the accumulator FRONTIER (the
// compact-range hashes) at the last rotation, so a restart rebuilds the
// current Merkle state from frontier + hot leaves without reading the cold
// tier. The property that matters is CONTINUITY: an accumulator restored from
// a frontier and fed the same subsequent leaves reaches the same root and
// size as the never-interrupted original — and proofs for post-frontier
// leaves still verify.

func fleaf(i int) []byte { return []byte(fmt.Sprintf("chain-hash-%03d", i)) }

// TestFrontierRoundTripContinuity is the keystone: split at every boundary of
// a 40-leaf tree, restore from the frontier, append the remainder, and
// require root and size to equal the uninterrupted accumulator's. A frontier
// that dropped or reordered a compact hash diverges the root immediately.
func TestFrontierRoundTripContinuity(t *testing.T) {
	const n = 40
	full := New()
	for i := 0; i < n; i++ {
		if err := full.AppendLeaf(fleaf(i)); err != nil {
			t.Fatal(err)
		}
	}
	wantRoot, err := full.Head()
	if err != nil {
		t.Fatal(err)
	}

	for cut := 1; cut < n; cut++ {
		pre := New()
		for i := 0; i < cut; i++ {
			if err := pre.AppendLeaf(fleaf(i)); err != nil {
				t.Fatal(err)
			}
		}
		size, hashes := pre.Frontier()
		if size != uint64(cut) {
			t.Fatalf("cut %d: frontier size = %d", cut, size)
		}
		restored, err := NewFromFrontier(size, hashes)
		if err != nil {
			t.Fatalf("cut %d: NewFromFrontier: %v", cut, err)
		}
		for i := cut; i < n; i++ {
			if err := restored.AppendLeaf(fleaf(i)); err != nil {
				t.Fatalf("cut %d: append %d on restored: %v", cut, i, err)
			}
		}
		gotRoot, err := restored.Head()
		if err != nil {
			t.Fatalf("cut %d: head: %v", cut, err)
		}
		if restored.Size() != n || !bytes.Equal(gotRoot, wantRoot) {
			t.Fatalf("cut %d: restored (root %x, size %d) != original (root %x, size %d) — "+
				"the frontier does not carry the whole prefix", cut, gotRoot, restored.Size(), wantRoot, n)
		}
	}
}

// TestFrontierRestoredServesHotInclusionProofs: a proof for a POST-frontier
// leaf from the restored accumulator verifies against the continued root. Cold
// (pre-frontier) proofs are the offline verifier's job, not the daemon's.
func TestFrontierRestoredServesHotInclusionProofs(t *testing.T) {
	const cut, n = 13, 21
	pre := New()
	for i := 0; i < cut; i++ {
		if err := pre.AppendLeaf(fleaf(i)); err != nil {
			t.Fatal(err)
		}
	}
	size, hashes := pre.Frontier()
	restored, err := NewFromFrontier(size, hashes)
	if err != nil {
		t.Fatal(err)
	}
	for i := cut; i < n; i++ {
		if err := restored.AppendLeaf(fleaf(i)); err != nil {
			t.Fatal(err)
		}
	}
	root, err := restored.Head()
	if err != nil {
		t.Fatal(err)
	}
	for i := cut; i < n; i++ {
		prf, err := restored.InclusionProof(uint64(i))
		if err != nil {
			t.Fatalf("inclusion proof for hot leaf %d from restored accumulator: %v", i, err)
		}
		if err := VerifyInclusion(uint64(i), n, fleaf(i), root, prf); err != nil {
			t.Fatalf("hot-leaf %d proof does not verify against the continued root: %v", i, err)
		}
	}
}

// TestFrontierTamperDiverges: any altered frontier hash must change the
// continued root (otherwise a checkpoint forgery could splice history).
func TestFrontierTamperDiverges(t *testing.T) {
	const cut, n = 8, 12
	pre := New()
	for i := 0; i < cut; i++ {
		if err := pre.AppendLeaf(fleaf(i)); err != nil {
			t.Fatal(err)
		}
	}
	size, hashes := pre.Frontier()
	if len(hashes) == 0 {
		t.Fatal("frontier of a non-empty tree has no hashes")
	}
	// Reference root continued from the honest frontier.
	honest, err := NewFromFrontier(size, hashes)
	if err != nil {
		t.Fatal(err)
	}
	for i := cut; i < n; i++ {
		if err := honest.AppendLeaf(fleaf(i)); err != nil {
			t.Fatal(err)
		}
	}
	honestRoot, err := honest.Head()
	if err != nil {
		t.Fatal(err)
	}

	tampered := make([][]byte, len(hashes))
	for i := range hashes {
		tampered[i] = append([]byte(nil), hashes[i]...)
	}
	tampered[0][0] ^= 0x01
	forged, err := NewFromFrontier(size, tampered)
	if err != nil {
		// Refusing outright is also a pass: the forgery did not survive.
		return
	}
	for i := cut; i < n; i++ {
		if err := forged.AppendLeaf(fleaf(i)); err != nil {
			return
		}
	}
	forgedRoot, err := forged.Head()
	if err != nil {
		return
	}
	if bytes.Equal(forgedRoot, honestRoot) {
		t.Fatal("a tampered frontier hash continued to the SAME root; the checkpoint " +
			"does not bind the cold prefix")
	}
}

// TestNewFromFrontierRefusesShapeMismatch: a hash count that cannot represent
// the claimed size is a malformed checkpoint, refused at construction.
func TestNewFromFrontierRefusesShapeMismatch(t *testing.T) {
	pre := New()
	for i := 0; i < 5; i++ {
		if err := pre.AppendLeaf(fleaf(i)); err != nil {
			t.Fatal(err)
		}
	}
	size, hashes := pre.Frontier()
	if _, err := NewFromFrontier(size, hashes[:len(hashes)-1]); err == nil {
		t.Fatal("a frontier with a missing compact hash was accepted for the claimed size")
	}
}
