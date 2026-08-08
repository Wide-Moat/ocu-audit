// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package chain

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/Wide-Moat/ocu-audit/internal/ocsf"
)

// NFR-SEC-48 requires the committed audit record to carry a pipeline-stamped
// TRUSTED wall-clock alongside the monotonic sequence. The source's occurred-at
// time rides the OCSF payload (untrusted, recorded); the trusted stamp is the
// pipeline's IngestTime.
//
// The stamp is only trustworthy if it is tamper-evident: an IngestTime outside
// the chain hash would be the one field on an otherwise hash-bound record that
// an attacker could backdate freely, which defeats calling it trusted (INV-3,
// NFR-SEC-03). These pin that IngestTime feeds the chain hash and that the
// per-record hash carries a domain tag.

func recWithIngest(ingest int64) *ocsf.Record {
	return &ocsf.Record{
		Source: "control-plane", Sequence: 1,
		TraceID: "t", SessionID: "s", ActorID: "a",
		Resource: "r", Action: "act", Outcome: ocsf.OutcomeSuccess,
		Payload:    json.RawMessage(`{"seq":1}`),
		IngestTime: ingest,
	}
}

// TestIngestTimeIsHashBound is the keystone. Two records identical but for
// IngestTime must produce different chain hashes — otherwise the trusted stamp
// is backdatable on a record that still verifies.
func TestIngestTimeIsHashBound(t *testing.T) {
	a := recWithIngest(1000)
	b := recWithIngest(2000)

	Author(a, GenesisPrevHash)
	Author(b, GenesisPrevHash)

	if hex.EncodeToString(a.ChainHash) == hex.EncodeToString(b.ChainHash) {
		t.Fatal("two records differing only in IngestTime hash identically; the " +
			"trusted wall-clock is not tamper-evident and can be backdated on a " +
			"record that still verifies")
	}
}

// TestVerifyRejectsATamperedIngestTime states the same property end to end
// through the verifier: flipping a committed record's IngestTime must break
// verification.
func TestVerifyRejectsATamperedIngestTime(t *testing.T) {
	rec := recWithIngest(1000)
	Author(rec, GenesisPrevHash)

	// The record as committed verifies.
	if !Verify(rec, GenesisPrevHash) {
		t.Fatal("a freshly authored record does not verify")
	}

	// Backdate the IngestTime without re-authoring: the stored ChainHash no
	// longer matches the recomputed one.
	rec.IngestTime = 500
	if Verify(rec, GenesisPrevHash) {
		t.Fatal("a record with a tampered IngestTime still verified; the trusted " +
			"stamp is outside the chain hash")
	}
}

// TestChainHashCarriesADomainTag pins the domain separation. The head envelope
// signs under "ocu-audit-head/v1"; the per-record chain hash had no tag, so a
// record hash could collide with another OCU hash construction over the same
// bytes. A tag scopes the hash to this use.
//
// It is checked by construction: a record hash must NOT equal a bare SHA-256
// over the same prev||seq||event bytes, because the tag now prefixes them.
func TestChainHashCarriesADomainTag(t *testing.T) {
	rec := recWithIngest(1000)
	Author(rec, GenesisPrevHash)

	untagged := untaggedComputeForTest(GenesisPrevHash, rec.Sequence, rec.CanonicalEventBytes())
	if hex.EncodeToString(rec.ChainHash) == hex.EncodeToString(untagged) {
		t.Fatal("the record chain hash equals an untagged SHA-256 over the same " +
			"inputs; the per-record hash carries no domain separation")
	}
}

// untaggedComputeForTest reproduces the OLD tagless hash (prev || BE64(seq) ||
// event), the construction this change replaces, so the domain-tag test can
// assert the new hash differs from it.
func untaggedComputeForTest(prev []byte, seq uint64, canonicalEvent []byte) []byte {
	h := sha256.New()
	h.Write(prev)
	var seqBuf [8]byte
	binary.BigEndian.PutUint64(seqBuf[:], seq)
	h.Write(seqBuf[:])
	h.Write(canonicalEvent)
	return h.Sum(nil)
}
