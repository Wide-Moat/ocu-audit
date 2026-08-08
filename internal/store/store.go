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
	"time"

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
	// clock is the trusted-time source IngestTime is stamped from (NFR-SEC-48).
	clock Clock
	// globalOffset is the number of rotated (cold) records preceding
	// records[0] in the global commit order (ADR-0045): zero on an
	// unrotated store. Proof indexes are GLOBAL; Records() stays hot-only.
	globalOffset uint64
	// ingestFloor is the highest IngestTime already committed. The stamp never
	// falls below it, so a wall-clock rollback cannot backdate a committed
	// record — a trusted stamp a rollback could lower would be no more
	// trustworthy than the source clock it exists to distrust.
	ingestFloor int64
}

// Clock supplies the pipeline's trusted wall-clock in epoch milliseconds. It is
// injected so a test can drive a rollback; production passes SystemClock.
type Clock interface {
	NowMillis() int64
}

// SystemClock reads the host wall-clock. The host trusted-time floor
// (NTS-anchored, monotonic per NFR-SEC-48) is the deployment's concern; the
// store additionally floors the stamp so an in-process regression cannot lower
// it.
type SystemClock struct{}

// NowMillis returns the current time in epoch milliseconds.
func (SystemClock) NowMillis() int64 { return time.Now().UnixMilli() }

type srcSeq struct {
	source string
	seq    uint64
}

// New wraps an open WAL with empty state. A restarting daemon must NOT serve
// this bare: it boots through Recover, which rebuilds the maps, records, and
// accumulator from the WAL (verifying the chains) before serving.
func New(w *wal.WAL, clk Clock) *Store {
	if clk == nil {
		clk = SystemClock{}
	}
	return &Store{
		w:                 w,
		perSourceLastHash: make(map[string][]byte),
		perSourceLastSeq:  make(map[string]uint64),
		seen:              make(map[srcSeq]struct{}),
		acc:               merkletree.New(),
		clock:             clk,
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
		// Trusted stamp, floored so a rollback cannot lower it (NFR-SEC-48).
		IngestTime: s.stampIngest(),
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

// SealSnapshot is the commit-order state at a seal point — exactly the
// anchors a rotation of the sealed prefix will promote into the retention
// checkpoint (ADR-0045). Captured under the store lock, so it is exact.
type SealSnapshot struct {
	// Count and TreeSize are the GLOBAL committed-record count and Merkle
	// size at the seal.
	Count    uint64
	TreeSize uint64
	// Frontier is the accumulator frontier at the seal.
	Frontier [][]byte
	// Tips is each source's last hash+sequence at the seal.
	Tips map[string]ChainTip
}

// SealActive seals the active WAL file to sealedPath (ADR-0045): under the
// store lock it delegates to the WAL seal and snapshots the seal-point
// anchors. Admit blocks for the seal's duration, so the snapshot is exact:
// every record in the sealed segment set is covered, none from after.
func (s *Store) SealActive(sealedPath string) (SealSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.w.SealTo(sealedPath); err != nil {
		return SealSnapshot{}, fmt.Errorf("store: seal: %w", err)
	}
	size, frontier := s.acc.Frontier()
	tips := make(map[string]ChainTip, len(s.perSourceLastHash))
	for src, h := range s.perSourceLastHash {
		tips[src] = ChainTip{Hash: append([]byte(nil), h...), Seq: s.perSourceLastSeq[src]}
	}
	return SealSnapshot{
		Count:    s.globalOffset + uint64(len(s.records)),
		TreeSize: size,
		Frontier: frontier,
		Tips:     tips,
	}, nil
}

// RecordsFrom returns the committed records at GLOBAL indexes >= from, in
// commit order. A from inside the rotated (cold) prefix returns only the hot
// records (the caller sees the gap via GlobalOffset) — the store never reads
// the cold tier.
func (s *Store) RecordsFrom(from uint64) []*ocsf.Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	if from < s.globalOffset {
		from = s.globalOffset
	}
	local := from - s.globalOffset
	if local >= uint64(len(s.records)) {
		return nil
	}
	out := make([]*ocsf.Record, len(s.records)-int(local))
	copy(out, s.records[local:])
	return out
}

// GlobalOffset returns the number of rotated (cold) records preceding the hot
// set — the boundary a fan-out cursor lagging past it has permanently missed
// (the cold tier still holds the records; the SINK does not).
func (s *Store) GlobalOffset() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.globalOffset
}

// GlobalCount returns the global committed-record count: rotated (cold)
// records plus the hot set. The retention manager's seal decision reads it.
func (s *Store) GlobalCount() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.globalOffset + uint64(len(s.records))
}

// LastSequence returns the last committed sequence for a source (0 if none).
// The ingest server seeds its self-emit sequence from it so the pipeline's
// own channel continues across a restart instead of regressing to 1 — a
// regressed self-emit would be refused and the evidence silently lost.
func (s *Store) LastSequence(source string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.perSourceLastSeq[source]
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
// given GLOBAL commit index. A rotated (cold) index is refused: the hot-only
// accumulator lacks the pre-frontier nodes, and cold proofs are the offline
// verifier's job over the full union (ADR-0045).
func (s *Store) InclusionProof(index uint64) ([][]byte, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if index < s.globalOffset {
		return nil, nil, fmt.Errorf("store: index %d is in the rotated cold prefix (< %d); use the offline verifier", index, s.globalOffset)
	}
	local := index - s.globalOffset
	if local >= uint64(len(s.records)) {
		return nil, nil, fmt.Errorf("store: index %d out of range (%d records from offset %d)", index, len(s.records), s.globalOffset)
	}
	prf, err := s.acc.InclusionProof(index)
	if err != nil {
		return nil, nil, err
	}
	return prf, s.records[local].ChainHash, nil
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

// stampIngest reads the trusted clock and applies the monotonic floor, so a
// committed IngestTime never regresses below one already committed. Called
// under the store lock.
func (s *Store) stampIngest() int64 {
	now := s.clock.NowMillis()
	if now < s.ingestFloor {
		now = s.ingestFloor
	}
	s.ingestFloor = now
	return now
}
