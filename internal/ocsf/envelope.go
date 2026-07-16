// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package ocsf models the audit fan-in message envelope and its canonical
// byte encoding. The envelope carries the OCU mandatory fields out-of-band of
// the OCSF payload (NFR-MAINT-AUDIT-SCHEMA); the payload is an opaque OCSF v1.x
// event class the pipeline neither parses nor trusts for identity.
//
// The pipeline authors the hash-chain linkage (prev_hash/chain_hash) at ingest
// and never reads it from a publish payload (INV-1/INV-3). The wire type here
// therefore has NO prev_hash/chain_hash field: a payload cannot even express a
// chain claim, which is a stronger structural guarantee than discarding one.
package ocsf

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// Outcome mirrors the OCSF status_id axis carried in the envelope.
type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailure Outcome = "failure"
	OutcomeUnknown Outcome = "unknown"
)

// Field bounds derived from the AuditEnvelope schema in
// contracts/audit/audit-fanin.asyncapi.yaml (NFR-SEC-51 defaults). A source
// exceeding a bound is rejected at decode, never truncated.
const (
	maxTraceID   = 128
	maxSessionID = 128
	maxActorID   = 256
	maxResource  = 1024
	maxAction    = 128
)

// PublishEnvelope is the wire shape a source POSTs. It deliberately omits any
// source, prev_hash, or chain_hash field: the OCSF source is the host-attested
// channel identity (INV-1) and the chain linkage is pipeline-authored (INV-3),
// so neither is expressible on the wire. additionalProperties is rejected so a
// smuggled "source"/"prev_hash" key fails the decode rather than being ignored.
type PublishEnvelope struct {
	TraceID   string          `json:"trace_id"`
	SessionID string          `json:"session_id"`
	ActorID   string          `json:"actor_id"`
	Resource  string          `json:"resource"`
	Action    string          `json:"action"`
	Outcome   Outcome         `json:"outcome"`
	Sequence  uint64          `json:"sequence"`
	Payload   json.RawMessage `json:"payload"`
}

// DecodePublish parses a wire envelope, rejecting any unknown field (so a
// payload-supplied source/prev_hash/chain_hash key is a hard error, not a
// silently-ignored value) and validating the mandatory-field bounds. It returns
// a *PublishEnvelope carrying only fields a source is allowed to set.
func DecodePublish(raw []byte) (*PublishEnvelope, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var e PublishEnvelope
	if err := dec.Decode(&e); err != nil {
		return nil, fmt.Errorf("decode publish envelope: %w", err)
	}
	// A single JSON value only: trailing tokens (a second object, junk) are a
	// malformed publish, not a partial accept.
	if dec.More() {
		return nil, errors.New("decode publish envelope: trailing data after JSON value")
	}
	if err := e.validate(); err != nil {
		return nil, err
	}
	return &e, nil
}

func (e *PublishEnvelope) validate() error {
	switch {
	case len(e.TraceID) == 0 || len(e.TraceID) > maxTraceID:
		return fmt.Errorf("trace_id length %d out of range (1..%d)", len(e.TraceID), maxTraceID)
	case len(e.SessionID) == 0 || len(e.SessionID) > maxSessionID:
		return fmt.Errorf("session_id length %d out of range (1..%d)", len(e.SessionID), maxSessionID)
	case len(e.ActorID) == 0 || len(e.ActorID) > maxActorID:
		return fmt.Errorf("actor_id length %d out of range (1..%d)", len(e.ActorID), maxActorID)
	case len(e.Resource) == 0 || len(e.Resource) > maxResource:
		return fmt.Errorf("resource length %d out of range (1..%d)", len(e.Resource), maxResource)
	case len(e.Action) == 0 || len(e.Action) > maxAction:
		return fmt.Errorf("action length %d out of range (1..%d)", len(e.Action), maxAction)
	}
	switch e.Outcome {
	case OutcomeSuccess, OutcomeFailure, OutcomeUnknown:
	default:
		return fmt.Errorf("outcome %q not in {success,failure,unknown}", e.Outcome)
	}
	if len(e.Payload) == 0 {
		return errors.New("payload is required")
	}
	if !json.Valid(e.Payload) {
		return errors.New("payload is not valid JSON")
	}
	return nil
}

// Record is a pipeline-authored, committed audit record. Source is the
// host-attested channel identity assigned at ingest (never from the payload);
// PrevHash and ChainHash are authored by the chain writer. This is the shape
// persisted to the WAL and re-read by the independent verifier.
type Record struct {
	Source    string          `json:"source"`
	Sequence  uint64          `json:"sequence"`
	TraceID   string          `json:"trace_id"`
	SessionID string          `json:"session_id"`
	ActorID   string          `json:"actor_id"`
	Resource  string          `json:"resource"`
	Action    string          `json:"action"`
	Outcome   Outcome         `json:"outcome"`
	Payload   json.RawMessage `json:"payload"`
	PrevHash  []byte          `json:"prev_hash"`
	ChainHash []byte          `json:"chain_hash"`
}

// CanonicalEventBytes returns the deterministic byte encoding of the event's
// identity fields (everything a source authored plus the host-attested source
// and sequence), EXCLUDING the chain linkage. The chain hash is computed over
// prior-hash || uint64-BE(sequence) || CanonicalEventBytes, so the linkage
// fields must not feed back into their own input. Encoding is length-prefixed
// per field so no two distinct field tuples can collide by concatenation.
func (r *Record) CanonicalEventBytes() []byte {
	var b bytes.Buffer
	writeField(&b, []byte(r.Source))
	writeU64(&b, r.Sequence)
	writeField(&b, []byte(r.TraceID))
	writeField(&b, []byte(r.SessionID))
	writeField(&b, []byte(r.ActorID))
	writeField(&b, []byte(r.Resource))
	writeField(&b, []byte(r.Action))
	writeField(&b, []byte(r.Outcome))
	writeField(&b, canonicalJSON(r.Payload))
	return b.Bytes()
}
