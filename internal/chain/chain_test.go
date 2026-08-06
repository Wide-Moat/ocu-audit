// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package chain

import (
	"encoding/json"
	"testing"

	"github.com/Wide-Moat/ocu-audit/internal/ocsf"
	"pgregory.net/rapid"
)

// buildChain authors a valid n-record chain for one source.
func buildChain(source string, n int) []*ocsf.Record {
	recs := make([]*ocsf.Record, 0, n)
	prev := GenesisPrevHash
	for i := 0; i < n; i++ {
		rec := &ocsf.Record{
			Source: source, Sequence: uint64(i + 1),
			TraceID: "t", SessionID: "s", ActorID: "a",
			Resource: "r", Action: "act", Outcome: ocsf.OutcomeSuccess,
			Payload: json.RawMessage(`{"i":` + itoa(i) + `}`),
		}
		Author(rec, prev)
		prev = rec.ChainHash
		recs = append(recs, rec)
	}
	return recs
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// TestVerifyChainGenesisOK asserts a freshly authored chain verifies.
func TestVerifyChainGenesisOK(t *testing.T) {
	recs := buildChain("control-plane", 5)
	if err := VerifyChain("control-plane", recs); err != nil {
		t.Fatalf("valid chain should verify, got %v", err)
	}
}

// TestVerifyChainDetectsTamper (property): mutating any field of any record in
// a valid chain makes VerifyChain fail. This is the tamper-evidence invariant.
func TestVerifyChainDetectsTamper(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(1, 8).Draw(t, "n")
		recs := buildChain("s", n)
		idx := rapid.IntRange(0, n-1).Draw(t, "idx")
		field := rapid.SampledFrom([]string{
			"actor", "resource", "action", "outcome", "payload", "chainhash", "prevhash",
		}).Draw(t, "field")
		switch field {
		case "actor":
			recs[idx].ActorID += "x"
		case "resource":
			recs[idx].Resource += "y"
		case "action":
			recs[idx].Action += "z"
		case "outcome":
			recs[idx].Outcome = ocsf.OutcomeFailure
		case "payload":
			recs[idx].Payload = json.RawMessage(`{"tampered":true}`)
		case "chainhash":
			recs[idx].ChainHash[0] ^= 0xff
		case "prevhash":
			recs[idx].PrevHash[0] ^= 0xff
		}
		if err := VerifyChain("s", recs); err == nil {
			t.Fatalf("tampering %q on record %d should break the chain", field, idx)
		}
	})
}

// TestVerifyChainDetectsReorder asserts swapping two adjacent records breaks it.
func TestVerifyChainDetectsReorder(t *testing.T) {
	recs := buildChain("s", 4)
	recs[1], recs[2] = recs[2], recs[1]
	if err := VerifyChain("s", recs); err == nil {
		t.Fatal("reordering records should break the chain")
	}
}

// TestVerifyChainDetectsDeletion asserts dropping a middle record breaks it.
func TestVerifyChainDetectsDeletion(t *testing.T) {
	recs := buildChain("s", 4)
	withGap := append([]*ocsf.Record{recs[0]}, recs[2], recs[3])
	if err := VerifyChain("s", withGap); err == nil {
		t.Fatal("deleting a middle record should break the chain")
	}
}

// TestGenesisPrevHashImmutable guards that Author copies prev, so mutating the
// caller's slice later cannot retroactively alter a record.
func TestGenesisPrevHashImmutable(t *testing.T) {
	rec := &ocsf.Record{Source: "s", Sequence: 1, TraceID: "t", SessionID: "s",
		ActorID: "a", Resource: "r", Action: "act", Outcome: ocsf.OutcomeSuccess,
		Payload: json.RawMessage(`{}`)}
	prev := make([]byte, HashSize)
	Author(rec, prev)
	prev[0] = 0xff // mutate caller slice after Author
	if rec.PrevHash[0] == 0xff {
		t.Fatal("Author must copy prev, not alias it")
	}
}
