// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package store

import (
	"fmt"

	"github.com/Wide-Moat/ocu-audit/internal/chain"
	"github.com/Wide-Moat/ocu-audit/internal/merkletree"
	"github.com/Wide-Moat/ocu-audit/internal/ocsf"
	"github.com/Wide-Moat/ocu-audit/internal/wal"
)

// ChainTip is one source's chain state at the rotation boundary: the last
// committed chain hash and sequence within the rotated (cold) prefix.
type ChainTip struct {
	Hash []byte
	Seq  uint64
}

// BootAnchor is the verified state hot-only boot anchors on (ADR-0045). The
// daemon derives it from the signed retention checkpoint AFTER signature and
// policy verification; the store trusts it as already authenticated.
type BootAnchor struct {
	// ChainTips carries each source's last hash+sequence within the rotated
	// prefix; a source absent here anchors on genesis.
	ChainTips map[string]ChainTip
	// TreeSize and Frontier are the Merkle accumulator state at the rotation
	// boundary.
	TreeSize uint64
	Frontier [][]byte
	// RotatedSegments names segments the checkpoint records as rotated; one
	// still present in hot (a crash before removal) is EXCLUDED from the boot
	// union — its records are cold-anchored, and the rotation manager
	// finishes the removal after boot.
	RotatedSegments []string
	// IngestFloor is the highest IngestTime within the rotated prefix, so the
	// NFR-SEC-48 monotonic floor spans records boot no longer reads.
	IngestFloor int64
}

// RecoverAnchored boots the store from the HOT tier plus the anchor, never
// reading the cold directory: hot chains verify from the anchored tips, the
// Merkle accumulator continues from the frontier, sequence tips and the
// IngestTime floor span the rotated prefix, and proofs serve at GLOBAL
// indexes (hot leaf i lives at anchor.TreeSize + i). Fail-closed: a hot
// record that does not link onto its anchored tip refuses boot.
func RecoverAnchored(activePath string, clk Clock, anchor BootAnchor) (*Store, error) {
	rotated := make(map[string]struct{}, len(anchor.RotatedSegments))
	for _, name := range anchor.RotatedSegments {
		rotated[name] = struct{}{}
	}
	records, err := readHotRecordsExcluding(activePath, rotated)
	if err != nil {
		return nil, fmt.Errorf("store: anchored recover: %w", err)
	}
	if err := verifyChainsAnchored(records, anchor.ChainTips); err != nil {
		return nil, fmt.Errorf("store: anchored recover: %w", err)
	}

	acc, err := merkletree.NewFromFrontier(anchor.TreeSize, anchor.Frontier)
	if err != nil {
		return nil, fmt.Errorf("store: anchored recover: %w", err)
	}

	w, err := wal.Open(activePath)
	if err != nil {
		return nil, fmt.Errorf("store: anchored recover: %w", err)
	}
	s := New(w, clk)
	s.acc = acc
	s.globalOffset = anchor.TreeSize
	s.ingestFloor = anchor.IngestFloor
	for src, tip := range anchor.ChainTips {
		s.perSourceLastHash[src] = append([]byte(nil), tip.Hash...)
		s.perSourceLastSeq[src] = tip.Seq
	}
	for i, rec := range records {
		s.perSourceLastHash[rec.Source] = rec.ChainHash
		s.perSourceLastSeq[rec.Source] = rec.Sequence
		s.seen[srcSeq{source: rec.Source, seq: rec.Sequence}] = struct{}{}
		s.records = append(s.records, rec)
		if rec.IngestTime > s.ingestFloor {
			s.ingestFloor = rec.IngestTime
		}
		if err := s.acc.AppendLeaf(rec.ChainHash); err != nil {
			_ = w.Close()
			return nil, fmt.Errorf("store: anchored recover: merkle append %d: %w", i, err)
		}
	}
	return s, nil
}

// verifyChainsAnchored groups hot records by source in commit order and
// verifies each source's linkage starting from its anchored tip (genesis for
// a source the anchor does not name).
func verifyChainsAnchored(records []*ocsf.Record, tips map[string]ChainTip) error {
	bySource := map[string][]*ocsf.Record{}
	var order []string
	for _, r := range records {
		if _, seen := bySource[r.Source]; !seen {
			order = append(order, r.Source)
		}
		bySource[r.Source] = append(bySource[r.Source], r)
	}
	for _, src := range order {
		if tip, anchored := tips[src]; anchored {
			if err := chain.VerifyChainAnchored(src, tip.Hash, tip.Seq, bySource[src]); err != nil {
				return err
			}
			continue
		}
		if err := chain.VerifyChain(src, bySource[src]); err != nil {
			return err
		}
	}
	return nil
}
