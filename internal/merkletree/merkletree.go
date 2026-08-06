// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package merkletree builds the daily Merkle head over the committed audit
// records and produces RFC-6962 inclusion and consistency proofs
// (component-07 INV-7, NFR-SEC-03). Leaves are the committed chain hashes in
// commit order; the head is the tree root. It uses
// github.com/transparency-dev/merkle (Apache-2.0) for the RFC-6962 log hasher,
// the compact-range root computation, and proof verification, so the tree math
// is a reviewed dependency, not re-derived here.
//
// The accumulator records every internal node hash as leaves are appended, so
// an inclusion proof for any leaf is served without re-reading the raw store.
package merkletree

import (
	"crypto"
	"fmt"

	_ "crypto/sha256" // register SHA-256 for crypto.SHA256

	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

// Accumulator builds the tree incrementally and remembers every node hash so
// it can serve proofs. It is not safe for concurrent use; the caller serializes
// appends (the chain writer is single-threaded per store).
type Accumulator struct {
	hasher *rfc6962.Hasher
	rf     *compact.RangeFactory
	rng    *compact.Range
	// nodes maps a compact node ID to its hash. It holds every node visited
	// while appending leaves and while computing the root, which together cover
	// every node any inclusion proof can reference.
	nodes map[compact.NodeID][]byte
	size  uint64
}

// New returns an empty accumulator over the RFC-6962 SHA-256 log hasher.
func New() *Accumulator {
	h := rfc6962.New(crypto.SHA256)
	rf := &compact.RangeFactory{Hash: h.HashChildren}
	return &Accumulator{
		hasher: h,
		rf:     rf,
		rng:    rf.NewEmptyRange(0),
		nodes:  make(map[compact.NodeID][]byte),
	}
}

// AppendLeaf adds one leaf. leafData is the raw leaf content (a committed chain
// hash); it is run through the RFC-6962 leaf hash (0x00 prefix) so a leaf can
// never be confused with an interior node (0x01 prefix). Every interior node
// created by the merge is recorded for later proof service.
func (a *Accumulator) AppendLeaf(leafData []byte) error {
	lh := a.hasher.HashLeaf(leafData)
	visit := func(id compact.NodeID, hash []byte) {
		h := make([]byte, len(hash))
		copy(h, hash)
		a.nodes[id] = h
	}
	// Record the leaf node itself (level 0).
	visit(compact.NewNodeID(0, a.size), lh)
	if err := a.rng.Append(lh, visit); err != nil {
		return fmt.Errorf("merkletree: append leaf %d: %w", a.size, err)
	}
	a.size++
	return nil
}

// Size returns the number of leaves appended so far.
func (a *Accumulator) Size() uint64 { return a.size }

// Head returns the current Merkle root (the daily head when called at cadence).
// It also records the right-border internal nodes so an inclusion proof against
// this head resolves fully from the node map.
func (a *Accumulator) Head() ([]byte, error) {
	if a.size == 0 {
		return a.hasher.EmptyRoot(), nil
	}
	visit := func(id compact.NodeID, hash []byte) {
		h := make([]byte, len(hash))
		copy(h, hash)
		a.nodes[id] = h
	}
	root, err := a.rng.GetRootHash(visit)
	if err != nil {
		return nil, fmt.Errorf("merkletree: root: %w", err)
	}
	return root, nil
}

// InclusionProof returns the RFC-6962 inclusion proof for the leaf at index
// against the current tree size. The proof is a list of sibling hashes ordered
// per RFC-6962; verify it with VerifyInclusion or the transparency-dev proof
// package.
func (a *Accumulator) InclusionProof(index uint64) ([][]byte, error) {
	if index >= a.size {
		return nil, fmt.Errorf("merkletree: index %d out of range for size %d", index, a.size)
	}
	// Ensure right-border nodes are populated (Head records them).
	if _, err := a.Head(); err != nil {
		return nil, err
	}
	nodes, err := proof.Inclusion(index, a.size)
	if err != nil {
		return nil, fmt.Errorf("merkletree: inclusion node set: %w", err)
	}
	hashes, err := a.resolve(nodes)
	if err != nil {
		return nil, err
	}
	return hashes, nil
}

// ConsistencyProof returns the RFC-6962 consistency proof between an earlier
// tree size and the current size. It proves the earlier head is a prefix of the
// current one (append-only, no rewrite).
func (a *Accumulator) ConsistencyProof(size1 uint64) ([][]byte, error) {
	if size1 > a.size {
		return nil, fmt.Errorf("merkletree: size1 %d > current %d", size1, a.size)
	}
	if _, err := a.Head(); err != nil {
		return nil, err
	}
	nodes, err := proof.Consistency(size1, a.size)
	if err != nil {
		return nil, fmt.Errorf("merkletree: consistency node set: %w", err)
	}
	return a.resolve(nodes)
}

// resolve turns a proof node set into the ordered hash list the RFC-6962
// verifier expects, rehashing ephemeral nodes from the recorded node map.
func (a *Accumulator) resolve(nodes proof.Nodes) ([][]byte, error) {
	hashes := make([][]byte, 0, len(nodes.IDs))
	for _, id := range nodes.IDs {
		h, ok := a.nodes[id]
		if !ok {
			return nil, fmt.Errorf("merkletree: missing node hash for id level=%d index=%d",
				id.Level, id.Index)
		}
		hashes = append(hashes, h)
	}
	return nodes.Rehash(hashes, a.hasher.HashChildren)
}

// VerifyInclusion checks an inclusion proof: that leafData is the leaf at index
// in a tree of the given size with the given root. It is the verifier-side
// check and does not touch the accumulator's internal state.
func VerifyInclusion(index, size uint64, leafData, root []byte, prf [][]byte) error {
	h := rfc6962.New(crypto.SHA256)
	return proof.VerifyInclusion(h, index, size, h.HashLeaf(leafData), prf, root)
}

// VerifyConsistency checks a consistency proof between two heads.
func VerifyConsistency(size1, size2 uint64, root1, root2 []byte, prf [][]byte) error {
	h := rfc6962.New(crypto.SHA256)
	return proof.VerifyConsistency(h, size1, size2, prf, root1, root2)
}

// RootFromLeaves recomputes the Merkle root from scratch over all leaf data in
// order. The verifier calls this to recompute the head independently of the
// accumulator, then compares it to the signed head.
func RootFromLeaves(leaves [][]byte) ([]byte, error) {
	acc := New()
	for i, l := range leaves {
		if err := acc.AppendLeaf(l); err != nil {
			return nil, fmt.Errorf("root-from-leaves: leaf %d: %w", i, err)
		}
	}
	return acc.Head()
}
