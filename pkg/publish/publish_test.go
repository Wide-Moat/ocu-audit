// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package publish

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func sampleEnvelope() Envelope {
	return Envelope{
		TraceID:   "t-1",
		SessionID: "s-1",
		ActorID:   "a-1",
		Resource:  "session/abc",
		Action:    "session.create",
		Outcome:   OutcomeSuccess,
		Sequence:  42,
		Payload:   json.RawMessage(`{"class_uid":6003}`),
	}
}

// A 200 ack is the only nil-error path: the source treats the action as durable
// ONLY when the ingest confirmed a committed, fsynced, chained write.
func TestPublish200IsAck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, err := NewWithHTTPClient(srv.Client(), srv.URL, "audit.ingest.control-plane")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.Publish(context.Background(), sampleEnvelope()); err != nil {
		t.Fatalf("Publish on 200 must be nil (ack), got %v", err)
	}
}

// Every non-200 is fail-closed: Publish returns a non-nil error so a caller
// coupling a privileged action to it denies the action. This is the anti-fake-
// green core -- a client that swallowed a 503 would let a source ack without a
// central commit (the exact gate-#3 hole).
func TestPublishNon200FailsClosed(t *testing.T) {
	for _, status := range []int{
		http.StatusBadRequest,          // 400 malformed / smuggled key
		http.StatusUnauthorized,        // 401 no client cert
		http.StatusForbidden,           // 403 peer not authorized for channel
		http.StatusConflict,            // 409 sequence regressed
		http.StatusServiceUnavailable,  // 503 fsync fault, not committed
		http.StatusInternalServerError, // 500 any other server failure
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "nope", status)
		}))
		c, err := NewWithHTTPClient(srv.Client(), srv.URL, "audit.ingest.control-plane")
		if err != nil {
			srv.Close()
			t.Fatalf("New: %v", err)
		}
		err = c.Publish(context.Background(), sampleEnvelope())
		srv.Close()
		if err == nil {
			t.Fatalf("status %d: Publish must fail closed (non-nil error), got nil", status)
		}
		var pe *PublishError
		if !errors.As(err, &pe) {
			t.Fatalf("status %d: want *PublishError, got %T (%v)", status, err, err)
		}
		if pe.Status != status {
			t.Fatalf("status %d: PublishError.Status = %d, want %d", status, pe.Status, status)
		}
		// 503 is the only retriable status; 4xx are terminal.
		wantRetriable := status == http.StatusServiceUnavailable
		if pe.Retriable() != wantRetriable {
			t.Fatalf("status %d: Retriable()=%v, want %v", status, pe.Retriable(), wantRetriable)
		}
	}
}

// A transport error (ingest unreachable) is fail-closed too, and is NOT a
// *PublishError (no HTTP status). This is the killed-ocu-audit case: the source
// must deny, not proceed.
func TestPublishTransportErrorFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	client := srv.Client()
	url := srv.URL
	srv.Close() // now unreachable -- the killed-ingest case

	c, err := NewWithHTTPClient(client, url, "audit.ingest.control-plane")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = c.Publish(context.Background(), sampleEnvelope())
	if err == nil {
		t.Fatal("Publish against a dead ingest must fail closed, got nil")
	}
	var pe *PublishError
	if errors.As(err, &pe) {
		t.Fatalf("a transport error must NOT be a *PublishError (no HTTP status), got %v", err)
	}
}

// The wire body is exactly the frozen contract: it POSTs to
// /v1alpha/audit/<channel>, carries the envelope fields, and carries NO
// source/prev_hash/chain_hash key (the server 400s those; the client must never
// emit them). This pins the wire shape against drift.
func TestPublishWireShape(t *testing.T) {
	var gotPath string
	var gotBody map[string]json.RawMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, err := NewWithHTTPClient(srv.Client(), srv.URL, "audit.ingest.control-plane")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.Publish(context.Background(), sampleEnvelope()); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	if want := "/v1alpha/audit/audit.ingest.control-plane"; gotPath != want {
		t.Fatalf("POST path = %q, want %q", gotPath, want)
	}
	// Required fields present.
	for _, k := range []string{"trace_id", "session_id", "actor_id", "resource", "action", "outcome", "sequence", "payload"} {
		if _, ok := gotBody[k]; !ok {
			t.Fatalf("wire body missing required field %q; got keys %v", k, keysOf(gotBody))
		}
	}
	// Forbidden fields absent -- a smuggled one is a 400 at the server and an
	// Inv-1/Inv-3 violation; the client must never marshal them.
	for _, k := range []string{"source", "prev_hash", "chain_hash"} {
		if _, ok := gotBody[k]; ok {
			t.Fatalf("wire body carries forbidden field %q (Inv-1/Inv-3); keys %v", k, keysOf(gotBody))
		}
	}
}

// New rejects a missing required field at construction, not at publish time.
func TestNewValidatesConfig(t *testing.T) {
	tlsCfg := &tls.Config{} // non-nil is all New checks; no handshake here
	cases := []Config{
		{Channel: "c", TLS: tlsCfg},          // no BaseURL
		{BaseURL: "https://a", TLS: tlsCfg},  // no Channel
		{BaseURL: "https://a", Channel: "c"}, // no TLS
	}
	for i, cfg := range cases {
		if _, err := New(cfg); err == nil {
			t.Fatalf("case %d: New must reject incomplete config, got nil", i)
		}
	}
	if _, err := New(Config{BaseURL: "https://a/", Channel: "c", TLS: tlsCfg}); err != nil {
		t.Fatalf("New on a complete config must succeed, got %v", err)
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}
