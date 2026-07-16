// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package merkletree

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"
)

func leaf(i int) []byte {
	h := sha256.Sum256([]byte(fmt.Sprintf("leaf-%d", i)))
	return h[:]
}

// TestHeadChangesOnAppend is the merkle-real anchor (i): appending one more leaf
// MUST change the head. A stub accumulator that ignores leaves would fail here.
func TestHeadChangesOnAppend(t *testing.T) {
	acc := New()
	for i := 0; i < 5; i++ {
		if err := acc.AppendLeaf(leaf(i)); err != nil {
			t.Fatal(err)
		}
	}
	h1, err := acc.Head()
	if err != nil {
		t.Fatal(err)
	}
	if err := acc.AppendLeaf(leaf(5)); err != nil {
		t.Fatal(err)
	}
	h2, err := acc.Head()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(h1, h2) {
		t.Fatal("head must change after appending a leaf (merkle-real)")
	}
}

// TestInclusionProofVerifies is the merkle-real anchor (ii) positive: a proof
// for a sampled leaf verifies against the head.
func TestInclusionProofVerifies(t *testing.T) {
	const n = 9
	acc := New()
	for i := 0; i < n; i++ {
		if err := acc.AppendLeaf(leaf(i)); err != nil {
			t.Fatal(err)
		}
	}
	head, _ := acc.Head()
	for idx := 0; idx < n; idx++ {
		prf, err := acc.InclusionProof(uint64(idx))
		if err != nil {
			t.Fatalf("proof[%d]: %v", idx, err)
		}
		if err := VerifyInclusion(uint64(idx), n, leaf(idx), head, prf); err != nil {
			t.Fatalf("verify inclusion[%d]: %v", idx, err)
		}
	}
}

// TestInclusionProofRejectsWrongLeaf asserts a proof for a leaf does not verify
// a DIFFERENT leaf against the head (proof is leaf-bound).
func TestInclusionProofRejectsWrongLeaf(t *testing.T) {
	const n = 6
	acc := New()
	for i := 0; i < n; i++ {
		_ = acc.AppendLeaf(leaf(i))
	}
	head, _ := acc.Head()
	prf, _ := acc.InclusionProof(2)
	if err := VerifyInclusion(2, n, leaf(3), head, prf); err == nil {
		t.Fatal("inclusion proof must not verify a different leaf")
	}
}

// TestInclusionProofRejectsTamperedHead asserts a tampered head fails.
func TestInclusionProofRejectsTamperedHead(t *testing.T) {
	const n = 7
	acc := New()
	for i := 0; i < n; i++ {
		_ = acc.AppendLeaf(leaf(i))
	}
	head, _ := acc.Head()
	bad := append([]byte(nil), head...)
	bad[0] ^= 0xff
	prf, _ := acc.InclusionProof(1)
	if err := VerifyInclusion(1, n, leaf(1), bad, prf); err == nil {
		t.Fatal("inclusion proof must not verify against a tampered head")
	}
}

// TestConsistencyProof asserts an earlier head is provably a prefix of a later
// one (append-only), and that an unrelated root fails.
func TestConsistencyProof(t *testing.T) {
	acc := New()
	for i := 0; i < 4; i++ {
		_ = acc.AppendLeaf(leaf(i))
	}
	head1, _ := acc.Head()
	for i := 4; i < 9; i++ {
		_ = acc.AppendLeaf(leaf(i))
	}
	head2, _ := acc.Head()
	prf, err := acc.ConsistencyProof(4)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyConsistency(4, 9, head1, head2, prf); err != nil {
		t.Fatalf("consistency 4->9 should verify: %v", err)
	}
	badHead1 := append([]byte(nil), head1...)
	badHead1[0] ^= 0xff
	if err := VerifyConsistency(4, 9, badHead1, head2, prf); err == nil {
		t.Fatal("consistency must fail against a wrong earlier head")
	}
}

// TestRootFromLeavesMatchesAccumulator asserts the independent recompute path
// (RootFromLeaves) equals the incremental accumulator head. The verifier relies
// on this equality.
func TestRootFromLeavesMatchesAccumulator(t *testing.T) {
	const n = 11
	acc := New()
	leaves := make([][]byte, n)
	for i := 0; i < n; i++ {
		leaves[i] = leaf(i)
		_ = acc.AppendLeaf(leaves[i])
	}
	accHead, _ := acc.Head()
	recomputed, err := RootFromLeaves(leaves)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(accHead, recomputed) {
		t.Fatal("RootFromLeaves must equal the incremental accumulator head")
	}
}
