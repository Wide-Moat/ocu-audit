// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package store

import (
	"encoding/json"
	"testing"

	"github.com/Wide-Moat/ocu-audit/internal/chain"
	"github.com/Wide-Moat/ocu-audit/internal/merkletree"
	"github.com/Wide-Moat/ocu-audit/internal/ocsf"
	"github.com/Wide-Moat/ocu-audit/internal/signer"
)

// buildSignedStore authors n records for one source, signs the head, and
// returns the raw records, signed head, and pinned pubkey. This is the fixture
// the red-probes neuter against.
func buildSignedStore(t *testing.T, n int) ([]*ocsf.Record, signer.SignedHead, []byte) {
	t.Helper()
	recs := make([]*ocsf.Record, 0, n)
	prev := chain.GenesisPrevHash
	acc := merkletree.New()
	for i := 0; i < n; i++ {
		rec := &ocsf.Record{Source: "control-plane", Sequence: uint64(i + 1),
			TraceID: "t", SessionID: "s", ActorID: "a", Resource: "r",
			Action: "act", Outcome: ocsf.OutcomeSuccess,
			Payload: json.RawMessage(`{"i":` + itoa(i) + `}`)}
		chain.Author(rec, prev)
		prev = rec.ChainHash
		if err := acc.AppendLeaf(rec.ChainHash); err != nil {
			t.Fatal(err)
		}
		recs = append(recs, rec)
	}
	head, _ := acc.Head()
	sgn, _ := signer.Generate()
	sh := sgn.Sign(signer.HeadEnvelope{Date: "2026-07-16", TreeSize: uint64(n), Head: head})
	return recs, sh, sgn.PublicKey()
}

// TestRedProbeBaselineGreen confirms the fixture verifies before any neuter, so
// a subsequent RED is caused by the neuter, not a broken fixture.
func TestRedProbeBaselineGreen(t *testing.T) {
	recs, sh, pub := buildSignedStore(t, 6)
	if _, err := VerifyStore(recs, sh, pub, 3); err != nil {
		t.Fatalf("baseline fixture must verify green: %v", err)
	}
}

// TestRedProbeChainTamperReds is the chain-linkage red-probe target: a single
// byte flipped in a middle record's chain hash makes VerifyStore RED. If the
// verifier skipped the chain recompute (a chain-linkage neuter), this would
// stay green.
func TestRedProbeChainTamperReds(t *testing.T) {
	recs, sh, pub := buildSignedStore(t, 6)
	recs[3].ChainHash[0] ^= 0xff
	if _, err := VerifyStore(recs, sh, pub, 3); err == nil {
		t.Fatal("chain tamper must red the verifier")
	}
}

// TestRedProbeHeadMismatchReds is the merkle-real red-probe (i): appending one
// more record without re-signing the head makes the recomputed head differ from
// the signed head, so VerifyStore reds.
func TestRedProbeHeadMismatchReds(t *testing.T) {
	recs, sh, pub := buildSignedStore(t, 6)
	extra := &ocsf.Record{Source: "control-plane", Sequence: 7,
		TraceID: "t", SessionID: "s", ActorID: "a", Resource: "r",
		Action: "act", Outcome: ocsf.OutcomeSuccess, Payload: json.RawMessage(`{"i":6}`)}
	chain.Author(extra, recs[5].ChainHash)
	recs = append(recs, extra)
	// sh still commits to size 6; the store now has 7 records.
	if _, err := VerifyStore(recs, sh, pub, 3); err == nil {
		t.Fatal("head must differ after an unsigned append (merkle-real i)")
	}
}

// TestRedProbeWrongKeyReds is the signer-real red-probe: verifying against a
// different pinned key reds. It never passes on "signature present".
func TestRedProbeWrongKeyReds(t *testing.T) {
	recs, sh, _ := buildSignedStore(t, 6)
	other, _ := signer.Generate()
	if _, err := VerifyStore(recs, sh, other.PublicKey(), 3); err == nil {
		t.Fatal("wrong pinned key must red the signature check (signer-real)")
	}
}

// TestRedProbeSequenceRegressionReds is the sequence red-probe at the verifier:
// a chain whose sequences are not strictly increasing reds. (Ingest also
// rejects this before commit; this proves the verifier is a second line.)
func TestRedProbeSequenceRegressionReds(t *testing.T) {
	recs, _, _ := buildSignedStore(t, 4)
	// Force a non-increasing sequence and re-author so the chain hashes are
	// internally consistent but the sequence order is violated.
	recs[2].Sequence = recs[1].Sequence // regress
	chain.Author(recs[2], recs[1].ChainHash)
	chain.Author(recs[3], recs[2].ChainHash)
	if _, err := VerifyChainsFromRaw(recs); err == nil {
		t.Fatal("sequence regression must red the chain verifier")
	}
}

// TestRedProbeInclusionAccumulatorNeuter is the merkle-real red-probe (ii):
// verifying an inclusion proof for record i against a head computed from a
// DIFFERENT leaf set (a neutered accumulator that dropped a leaf) fails.
func TestRedProbeInclusionAccumulatorNeuter(t *testing.T) {
	recs, _, _ := buildSignedStore(t, 6)
	full := make([][]byte, len(recs))
	for i, r := range recs {
		full[i] = r.ChainHash
	}
	// Neutered accumulator: drop the last leaf (size 5 not 6).
	neutered := full[:5]
	neuterHead, _ := merkletree.RootFromLeaves(neutered)
	acc := merkletree.New()
	for _, l := range full {
		_ = acc.AppendLeaf(l)
	}
	prf, _ := acc.InclusionProof(3)
	// Proof built over the full tree cannot verify against the neutered head.
	if err := merkletree.VerifyInclusion(3, 6, recs[3].ChainHash, neuterHead, prf); err == nil {
		t.Fatal("inclusion proof must not verify against a neutered accumulator head")
	}
}
