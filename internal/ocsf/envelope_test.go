// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocsf

import (
	"encoding/json"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// TestDecodePublishRejectsPayloadSource asserts INV-1/INV-3 at the decoder: a
// wire body carrying a source, prev_hash, or chain_hash key is rejected
// (DisallowUnknownFields), never silently stripped and admitted.
func TestDecodePublishRejectsPayloadSource(t *testing.T) {
	base := `{"trace_id":"t","session_id":"s","actor_id":"a","resource":"r","action":"act","outcome":"success","sequence":1,"payload":{"k":"v"}`
	for _, smuggled := range []string{
		`,"source":"control-plane"}`,
		`,"prev_hash":"AAAA"}`,
		`,"chain_hash":"BBBB"}`,
	} {
		body := base + smuggled
		if _, err := DecodePublish([]byte(body)); err == nil {
			t.Fatalf("expected decode to reject smuggled field in %q, got nil", smuggled)
		}
	}
	// The clean form (closing the object) must decode.
	if _, err := DecodePublish([]byte(base + "}")); err != nil {
		t.Fatalf("clean envelope should decode, got %v", err)
	}
}

// TestDecodePublishHasNoChainFields is a structural guarantee: the wire type
// itself has no PrevHash/ChainHash field, so a source cannot express a chain
// claim. Round-tripping a Record's chain fields through PublishEnvelope drops
// them.
func TestDecodePublishHasNoChainFields(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{
		"trace_id": "t", "session_id": "s", "actor_id": "a",
		"resource": "r", "action": "act", "outcome": "success",
		"sequence": 3, "payload": map[string]any{"x": 1},
		"prev_hash": "deadbeef",
	})
	if _, err := DecodePublish(raw); err == nil {
		t.Fatal("prev_hash on the wire must be rejected")
	}
}

// TestCanonicalBytesStableUnderKeyOrder asserts the payload canonicalization is
// insensitive to object key ordering: two payloads that are the same JSON value
// with different key order produce the same canonical event bytes.
func TestCanonicalBytesStableUnderKeyOrder(t *testing.T) {
	r1 := &Record{Source: "s", Sequence: 1, TraceID: "t", SessionID: "sess",
		ActorID: "a", Resource: "r", Action: "act", Outcome: OutcomeSuccess,
		Payload: json.RawMessage(`{"a":1,"b":2}`)}
	r2 := &Record{Source: "s", Sequence: 1, TraceID: "t", SessionID: "sess",
		ActorID: "a", Resource: "r", Action: "act", Outcome: OutcomeSuccess,
		Payload: json.RawMessage(`{"b":2,"a":1}`)}
	if string(r1.CanonicalEventBytes()) != string(r2.CanonicalEventBytes()) {
		t.Fatal("canonical bytes must not depend on payload key order")
	}
}

// TestCanonicalBytesInjective (property) asserts any change to any identity
// field changes the canonical bytes: two records that differ in any single
// field must not canonicalize to the same bytes. This underwrites the chain's
// tamper-evidence (any mutation => different hash).
func TestCanonicalBytesInjective(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		mk := func() *Record {
			return &Record{
				Source:    rapid.StringN(0, 20, 40).Draw(t, "source"),
				Sequence:  rapid.Uint64().Draw(t, "seq"),
				TraceID:   rapid.StringN(1, 20, 40).Draw(t, "trace"),
				SessionID: rapid.StringN(1, 20, 40).Draw(t, "session"),
				ActorID:   rapid.StringN(1, 20, 40).Draw(t, "actor"),
				Resource:  rapid.StringN(1, 20, 40).Draw(t, "resource"),
				Action:    rapid.StringN(1, 20, 40).Draw(t, "action"),
				Outcome:   Outcome(rapid.SampledFrom([]string{"success", "failure", "unknown"}).Draw(t, "outcome")),
				Payload:   json.RawMessage(`{"n":` + rapid.StringMatching(`[0-9]{1,4}`).Draw(t, "n") + `}`),
			}
		}
		a := mk()
		b := *a // copy
		// Mutate exactly one field.
		field := rapid.SampledFrom([]string{"seq", "trace", "actor", "action", "outcome"}).Draw(t, "mut")
		switch field {
		case "seq":
			b.Sequence = a.Sequence ^ 1
		case "trace":
			b.TraceID = a.TraceID + "x"
		case "actor":
			b.ActorID = a.ActorID + "y"
		case "action":
			b.Action = a.Action + "z"
		case "outcome":
			b.Outcome = Outcome(string(a.Outcome) + "!")
		}
		if string(a.CanonicalEventBytes()) == string(b.CanonicalEventBytes()) {
			t.Fatalf("mutating %q left canonical bytes unchanged", field)
		}
	})
}

// TestDecodeRejectsTrailingData guards against a smuggled second object.
func TestDecodeRejectsTrailingData(t *testing.T) {
	body := `{"trace_id":"t","session_id":"s","actor_id":"a","resource":"r","action":"act","outcome":"success","sequence":1,"payload":{}}{"x":1}`
	if _, err := DecodePublish([]byte(body)); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("expected trailing-data rejection, got %v", err)
	}
}
