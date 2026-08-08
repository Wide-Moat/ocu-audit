// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package chain

import (
	"crypto/subtle"
	"fmt"

	"github.com/Wide-Moat/ocu-audit/internal/ocsf"
)

// equalHash reports byte equality in constant time.
func equalHash(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// VerifyChain walks a single source's records in commit order and checks the
// full linkage from genesis: each record's PrevHash equals its predecessor's
// ChainHash (GenesisPrevHash for the first), each record's ChainHash recomputes
// from its own fields, and the per-source sequence is strictly increasing. Any
// mutated, reordered, inserted, or deleted record breaks one of these and
// returns an error naming the offending index.
//
// This is the anti-fake-green core: it recomputes hashes from the raw record
// fields, never trusting a stored ChainHash as an oracle.
func VerifyChain(source string, records []*ocsf.Record) error {
	return verifyChainFrom(source, GenesisPrevHash, 0, false, records)
}

// VerifyChainAnchored verifies a source's linkage starting from an anchored
// tip instead of genesis (ADR-0045 hot-only boot): the first record's
// PrevHash must equal anchorHash and its sequence must exceed anchorSeq, so a
// hot suffix that does not continue the rotated prefix refuses.
func VerifyChainAnchored(source string, anchorHash []byte, anchorSeq uint64, records []*ocsf.Record) error {
	return verifyChainFrom(source, anchorHash, anchorSeq, true, records)
}

func verifyChainFrom(source string, prev []byte, lastSeq uint64, haveSeq bool, records []*ocsf.Record) error {
	for i, rec := range records {
		if rec.Source != source {
			return fmt.Errorf("source %q record %d: carries source %q", source, i, rec.Source)
		}
		if haveSeq && rec.Sequence <= lastSeq {
			return fmt.Errorf("source %q record %d: sequence %d not strictly greater than %d",
				source, i, rec.Sequence, lastSeq)
		}
		if !Verify(rec, prev) {
			return fmt.Errorf("source %q record %d (sequence %d): chain linkage invalid",
				source, i, rec.Sequence)
		}
		prev = rec.ChainHash
		lastSeq = rec.Sequence
		haveSeq = true
	}
	return nil
}
