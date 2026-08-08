// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package store

import (
	"errors"
	"fmt"
	"os"

	"github.com/Wide-Moat/ocu-audit/internal/wal"
)

// Recover opens the WAL at path and rebuilds the store's full serving state —
// per-source chain tips, per-source sequence tips, the (source, sequence)
// dedupe set, the committed-record list, and the Merkle accumulator — from the
// committed records, VERIFYING every per-source chain from genesis before
// serving. Verification reuses the independent verifier's chain-link logic
// (VerifyChainsFromRaw), so the daemon and the verifier share one source of
// truth: a corrupt or tampered WAL REFUSES to boot (fail-closed) instead of
// serving an amnesiac store whose next admit would re-anchor a chain on
// genesis and leave the WAL permanently unverifiable.
//
// An absent WAL is a first boot: an empty store over a freshly created WAL.
func Recover(path string, clk Clock) (*Store, error) {
	records, err := ReadRawRecords(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("store: recover: %w", err)
		}
		records = nil // first boot: no WAL yet
	}
	if _, err := VerifyChainsFromRaw(records); err != nil {
		return nil, fmt.Errorf("store: recover: %w", err)
	}

	w, err := wal.Open(path)
	if err != nil {
		return nil, fmt.Errorf("store: recover: %w", err)
	}
	s := New(w, clk)
	for i, rec := range records {
		s.perSourceLastHash[rec.Source] = rec.ChainHash
		s.perSourceLastSeq[rec.Source] = rec.Sequence
		s.seen[srcSeq{source: rec.Source, seq: rec.Sequence}] = struct{}{}
		s.records = append(s.records, rec)
		// The IngestTime monotonic floor survives the restart: without this, a
		// wall-clock rollback ACROSS a restart would stamp a new record below a
		// committed IngestTime — the exact backdating NFR-SEC-48's floor exists
		// to prevent, reopened through the boot path.
		if rec.IngestTime > s.ingestFloor {
			s.ingestFloor = rec.IngestTime
		}
		if err := s.acc.AppendLeaf(rec.ChainHash); err != nil {
			_ = w.Close()
			return nil, fmt.Errorf("store: recover: merkle append %d: %w", i, err)
		}
	}
	return s, nil
}

// Close closes the underlying WAL. After Close, Admit refuses (wal.ErrClosed).
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Close()
}
