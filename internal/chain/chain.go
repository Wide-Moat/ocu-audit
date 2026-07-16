// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package chain implements the per-source, pipeline-authored hash chain
// (component-07 INV-3, NFR-SEC-03). Each source has its own chain; a record's
// chain hash links to its predecessor so any mutation, reorder, insertion, or
// deletion of a committed record breaks the chain and is detectable by the
// independent verifier.
//
// The hash is SHA-256 over:
//
//	prior-hash-bytes || uint64-BE(sequence) || canonical-event-bytes
//
// prior-hash-bytes is the predecessor record's chain hash, or GenesisPrevHash
// for the first record on a source. The linkage is authored here at ingest and
// is NEVER read from a publish payload: the wire envelope cannot even express
// prev_hash/chain_hash (see internal/ocsf), so this package is the sole author.
//
// This is a clean-room implementation. It does not import ocu-control internals.
package chain

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/Wide-Moat/ocu-audit/internal/ocsf"
)

// HashSize is the SHA-256 digest length in bytes.
const HashSize = sha256.Size

// GenesisPrevHash is the fixed prior-hash for the first record on any source:
// 32 zero bytes. A distinct, well-known genesis anchor lets the verifier start
// from a known point rather than trusting the first record's stored PrevHash.
var GenesisPrevHash = make([]byte, HashSize)

// Compute returns the chain hash of a record given its predecessor's chain hash.
// prev must be the predecessor's ChainHash, or GenesisPrevHash for the first
// record on the source. The returned slice is a fresh HashSize-byte value.
func Compute(prev []byte, seq uint64, canonicalEvent []byte) []byte {
	h := sha256.New()
	h.Write(prev)
	var seqBuf [8]byte
	binary.BigEndian.PutUint64(seqBuf[:], seq)
	h.Write(seqBuf[:])
	h.Write(canonicalEvent)
	return h.Sum(nil)
}

// Author fills a record's PrevHash and ChainHash from the predecessor's chain
// hash (or GenesisPrevHash for the first record). It authors the linkage from
// the record's OWN host-attested fields and the given prev, never from any
// payload-carried value. The record's Source and Sequence must already be set
// to the host-attested channel identity and the enforced sequence.
func Author(rec *ocsf.Record, prev []byte) {
	p := make([]byte, HashSize)
	copy(p, prev)
	rec.PrevHash = p
	rec.ChainHash = Compute(p, rec.Sequence, rec.CanonicalEventBytes())
}

// Verify recomputes a record's chain hash from prev and its canonical event
// bytes and reports whether the stored PrevHash and ChainHash both match. It is
// the verifier-side check: any field mutation changes CanonicalEventBytes and
// flips this to false; a tampered PrevHash breaks the linkage to the
// predecessor. equalHash is constant-time to keep the check side-channel-free.
func Verify(rec *ocsf.Record, prev []byte) bool {
	if !equalHash(rec.PrevHash, prev) {
		return false
	}
	want := Compute(rec.PrevHash, rec.Sequence, rec.CanonicalEventBytes())
	return equalHash(rec.ChainHash, want)
}
