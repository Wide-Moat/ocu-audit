// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package store

import (
	"fmt"

	"github.com/Wide-Moat/ocu-audit/internal/chain"
	"github.com/Wide-Moat/ocu-audit/internal/merkletree"
	"github.com/Wide-Moat/ocu-audit/internal/ocsf"
	"github.com/Wide-Moat/ocu-audit/internal/signer"
)

// VerifyResult reports the outcome of a full-store verification.
type VerifyResult struct {
	Sources     []string
	RecordCount int
	Head        []byte
}

// VerifyChainsFromRaw groups raw records by source (preserving per-source
// commit order) and verifies every source chain from genesis. It returns the
// ordered source labels seen. Any tamper, reorder, insertion, deletion, or
// sequence regression in any source chain returns an error.
func VerifyChainsFromRaw(records []*ocsf.Record) ([]string, error) {
	bySource := map[string][]*ocsf.Record{}
	var order []string
	for _, r := range records {
		if _, seen := bySource[r.Source]; !seen {
			order = append(order, r.Source)
		}
		bySource[r.Source] = append(bySource[r.Source], r)
	}
	for _, src := range order {
		if err := chain.VerifyChain(src, bySource[src]); err != nil {
			return nil, err
		}
	}
	return order, nil
}

// RecomputeHead recomputes the Merkle head from the committed chain hashes in
// commit order (the global record order, which is the leaf order). It is
// independent of any accumulator that produced the signed head.
func RecomputeHead(records []*ocsf.Record) ([]byte, error) {
	leaves := make([][]byte, len(records))
	for i, r := range records {
		leaves[i] = r.ChainHash
	}
	return merkletree.RootFromLeaves(leaves)
}

// VerifyStore runs the full anti-fake-green verification against a raw record
// set and a signed head: (1) every per-source chain verifies from genesis,
// (2) the recomputed head equals the signed head's head, (3) the envelope
// signature verifies against the pinned public key, and (4) a sampled
// inclusion proof verifies against the head. It returns a VerifyResult or the
// first failure.
func VerifyStore(records []*ocsf.Record, sh signer.SignedHead, pinnedPub []byte, sampleIndex uint64) (*VerifyResult, error) {
	order, err := VerifyChainsFromRaw(records)
	if err != nil {
		return nil, fmt.Errorf("chain verification: %w", err)
	}

	head, err := RecomputeHead(records)
	if err != nil {
		return nil, fmt.Errorf("recompute head: %w", err)
	}
	if uint64(len(records)) != sh.Envelope.TreeSize {
		return nil, fmt.Errorf("tree size mismatch: store has %d records, signed head claims %d",
			len(records), sh.Envelope.TreeSize)
	}
	if !bytesEqualCT(head, sh.Envelope.Head) {
		return nil, fmt.Errorf("head mismatch: recomputed head does not equal signed head")
	}

	if err := signer.Verify(sh, pinnedPub); err != nil {
		return nil, fmt.Errorf("envelope signature: %w", err)
	}

	if len(records) > 0 {
		if sampleIndex >= uint64(len(records)) {
			return nil, fmt.Errorf("sample index %d out of range (%d records)", sampleIndex, len(records))
		}
		acc := merkletree.New()
		for i, r := range records {
			if err := acc.AppendLeaf(r.ChainHash); err != nil {
				return nil, fmt.Errorf("rebuild accumulator leaf %d: %w", i, err)
			}
		}
		prf, err := acc.InclusionProof(sampleIndex)
		if err != nil {
			return nil, fmt.Errorf("build inclusion proof: %w", err)
		}
		if err := merkletree.VerifyInclusion(
			sampleIndex, uint64(len(records)), records[sampleIndex].ChainHash, head, prf); err != nil {
			return nil, fmt.Errorf("inclusion proof for record %d: %w", sampleIndex, err)
		}
	}

	return &VerifyResult{Sources: order, RecordCount: len(records), Head: head}, nil
}

func bytesEqualCT(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
