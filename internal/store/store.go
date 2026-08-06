// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package store is the chain writer and durable-commit coordinator. It owns
// the WAL (the durable bus / local commit), the per-source sequence state, the
// per-source hash chains, and the daily Merkle accumulator. Ingest admits an
// event only after: the sequence is strictly monotonic per source (dedupe on
// exact replay), the chain hash is authored from the host-attested source, and
// the record is fsync-committed to the WAL. Ack is licensed by a nil return
// from Admit (INV-4).
//
// The store is the sole author of chain linkage (INV-3): callers pass a
// host-attested source and a decoded publish envelope; they never supply
// prev_hash/chain_hash.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/Wide-Moat/ocu-audit/internal/chain"
	"github.com/Wide-Moat/ocu-audit/internal/merkletree"
	"github.com/Wide-Moat/ocu-audit/internal/ocsf"
	"github.com/Wide-Moat/ocu-audit/internal/wal"
)

// ErrSequenceRegressed is returned when a source publishes a sequence that is
// not strictly greater than its last committed sequence and is not an exact
// replay of the immediate predecessor.
var ErrSequenceRegressed = errors.New("store: sequence not strictly increasing")

// ErrDuplicate is returned when an exact (source, sequence) replay is seen; the
// caller treats it as idempotent success (already committed) but no new record
// is appended.
var ErrDuplicate = errors.New("store: duplicate (source, sequence)")

// Store coordinates durable commit and chain authorship.
type Store struct {
	mu sync.Mutex
	w  *wal.WAL
	// perSourceLastHash is the last committed chain hash per source (genesis if
	// absent).
	perSourceLastHash map[string][]byte
	// perSourceLastSeq is the last committed sequence per source.
	perSourceLastSeq map[string]uint64
	// seen dedupes exact (source, sequence) replays.
	seen map[srcSeq]struct{}
	// records is the in-commit-order list of committed records (the Merkle leaf
	// order). It mirrors the WAL, kept in memory for head/proof service.
	records []*ocsf.Record
	acc     *merkletree.Accumulator
}

type srcSeq struct {
	source string
	seq    uint64
}

// New wraps an open WAL. On a fresh WAL the maps are empty; a recovering store
// rebuilds them with Replay before serving.
func New(w *wal.WAL) *Store {
	return &Store{
		w:                 w,
		perSourceLastHash: make(map[string][]byte),
		perSourceLastSeq:  make(map[string]uint64),
		seen:              make(map[srcSeq]struct{}),
		acc:               merkletree.New(),
	}
}

// Admit validates, chains, and durably commits one event under the given
// host-attested source. A nil return means the record is fsync-committed and
// the caller may ack (INV-4). ErrDuplicate is an idempotent no-op success for
// the caller. Any other error means NOT committed: do not ack, chains stay
// unbroken because nothing was appended.
func (s *Store) Admit(source string, env *ocsf.PublishEnvelope) (*ocsf.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := srcSeq{source: source, seq: env.Sequence}
	if _, dup := s.seen[key]; dup {
		return nil, ErrDuplicate
	}
	if last, ok := s.perSourceLastSeq[source]; ok && env.Sequence <= last {
		return nil, fmt.Errorf("%w: source %q seq %d <= last %d",
			ErrSequenceRegressed, source, env.Sequence, last)
	}

	prev := s.perSourceLastHash[source]
	if prev == nil {
		prev = chain.GenesisPrevHash
	}

	rec := &ocsf.Record{
		Source:    source, // host-attested, never from payload (INV-1)
		Sequence:  env.Sequence,
		TraceID:   env.TraceID,
		SessionID: env.SessionID,
		ActorID:   env.ActorID,
		Resource:  env.Resource,
		Action:    env.Action,
		Outcome:   env.Outcome,
		Payload:   env.Payload,
	}
	chain.Author(rec, prev) // authors PrevHash/ChainHash (INV-3)

	// The WAL frame IS the pipeline-authored ocsf.Record, serialized as-is: the
	// WAL frames and CRCs it, the store hash-chains it. It carried a walRecord
	// alias to say so, which left an unreferenced type once the no-op
	// conversion went; the sentence says it without one.
	frame, err := json.Marshal(rec)
	if err != nil {
		return nil, fmt.Errorf("store: marshal record: %w", err)
	}
	// Durable commit BEFORE any in-memory state advances or ack is licensed.
	if err := s.w.Append(frame); err != nil {
		// Not committed: leave all state untouched so the chain is unbroken and
		// a retry with the same sequence is still admissible.
		return nil, fmt.Errorf("store: durable commit failed: %w", err)
	}

	// Committed: advance state.
	s.perSourceLastHash[source] = rec.ChainHash
	s.perSourceLastSeq[source] = env.Sequence
	s.seen[key] = struct{}{}
	s.records = append(s.records, rec)
	if err := s.acc.AppendLeaf(rec.ChainHash); err != nil {
		// The record is durably committed; a Merkle append failure is a
		// programming error (append is total for well-formed input). Surface it
		// loud rather than silently diverging the head from the store.
		return rec, fmt.Errorf("store: merkle append after commit: %w", err)
	}
	return rec, nil
}

// Head returns the current Merkle head over all committed records.
func (s *Store) Head() ([]byte, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	root, err := s.acc.Head()
	if err != nil {
		return nil, 0, err
	}
	return root, s.acc.Size(), nil
}

// InclusionProof returns the inclusion proof for the committed record at the
// given global commit index.
func (s *Store) InclusionProof(index uint64) ([][]byte, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if index >= uint64(len(s.records)) {
		return nil, nil, fmt.Errorf("store: index %d out of range (%d records)", index, len(s.records))
	}
	prf, err := s.acc.InclusionProof(index)
	if err != nil {
		return nil, nil, err
	}
	return prf, s.records[index].ChainHash, nil
}

// FaultWALForTest injects a WAL syncer fault. It is the durability
// fault-injection seam the audit-path chaos tests drive (component-07 INV-4:
// prove no ack is issued when the durable commit cannot be guaranteed). It is
// exported for cross-package tests; production wiring never calls it.
func FaultWALForTest(s *Store, syncer wal.Syncer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.w.SetSyncer(syncer)
}

// Records returns a snapshot of committed records in commit order.
func (s *Store) Records() []*ocsf.Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*ocsf.Record, len(s.records))
	copy(out, s.records)
	return out
}
