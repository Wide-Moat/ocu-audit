// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingest

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Wide-Moat/ocu-audit/internal/signer"
	"github.com/Wide-Moat/ocu-audit/internal/store"
	"github.com/Wide-Moat/ocu-audit/internal/wal"
)

// keystoneRig stands up the real mTLS ingest face over two synthetic sources
// (control-plane, object-store) and returns the pieces the keystone drives.
type keystoneRig struct {
	srv      *httptest.Server
	ca       *testCA
	walPath  string
	store    *store.Store
	signer   *signer.Signer
	headPath string
}

func newKeystoneRig(t *testing.T) *keystoneRig {
	t.Helper()
	ca := newTestCA(t)
	walPath := filepath.Join(t.TempDir(), "keystone.wal")
	w, err := wal.Open(walPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	st := store.New(w)
	sgn, err := signer.Generate()
	if err != nil {
		t.Fatal(err)
	}

	// The control-plane peer is also the exec-driver authorized to host-author
	// the session-sandbox channel (NFR-SEC-47).
	authz := DefaultAuthz("control-plane")
	handler := NewServer(st, authz, MTLSPeerVerifier{}).Handler()

	srv := httptest.NewUnstartedServer(handler)
	serverCert := ca.leaf(t, "ocu-audit", true)
	srv.TLS = ServerTLSConfig(serverCert, ca.pool)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	return &keystoneRig{
		srv:      srv,
		ca:       ca,
		walPath:  walPath,
		store:    st,
		signer:   sgn,
		headPath: filepath.Join(t.TempDir(), "head.json"),
	}
}

// clientFor builds an HTTP client that presents the given peer CN's client
// certificate over mTLS.
func (r *keystoneRig) clientFor(t *testing.T, peerCN string) *http.Client {
	t.Helper()
	clientCert := r.ca.leaf(t, peerCN, false)
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{clientCert},
				RootCAs:      r.ca.pool,
				MinVersion:   tls.VersionTLS13,
			},
		},
	}
}

// publish POSTs an OCSF event body to a channel address as the given peer.
func (r *keystoneRig) publish(t *testing.T, client *http.Client, address string, body []byte) *http.Response {
	t.Helper()
	url := r.srv.URL + "/v1alpha/audit/" + address
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("publish to %s: %v", address, err)
	}
	// Closed here rather than at each call site: every caller wants the status
	// or the decoded body and none wants the descriptor, so leaving the close
	// to them leaked one connection per publish across the keystone suites.
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func event(seq uint64, actor string) []byte {
	b, _ := json.Marshal(map[string]any{
		"trace_id": "trace-" + actor, "session_id": "sess-" + actor,
		"actor_id": actor, "resource": "res", "action": "act",
		"outcome": "success", "sequence": seq,
		"payload": map[string]any{"seq": seq, "who": actor},
	})
	return b
}

// signHead signs the current head and writes it to headPath, returning the
// pinned public key hex.
func (r *keystoneRig) signHead(t *testing.T) string {
	t.Helper()
	head, size, err := r.store.Head()
	if err != nil {
		t.Fatal(err)
	}
	sh := r.signer.Sign(signer.HeadEnvelope{Date: "2026-07-16", TreeSize: size, Head: head})
	b, _ := signer.MarshalSignedHead(sh)
	if err := os.WriteFile(r.headPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(r.signer.PublicKey())
}

// TestKeystone is the firsthand keystone: two synthetic sources POST OCSF
// events over the real mTLS ingest face into two per-source chains; the
// independent verifier passes from genesis; the daily head is signed; an
// inclusion proof for a sampled record verifies against the head AND the
// envelope signature verifies; a cross-channel publish is rejected (INV-2)
// with nothing admitted; and the whole store verifies end to end.
func TestKeystone(t *testing.T) {
	rig := newKeystoneRig(t)
	control := rig.clientFor(t, "control-plane")
	objstore := rig.clientFor(t, "object-store")

	// Two sources, each publishing an interleaved sequence into its own chain.
	for seq := uint64(1); seq <= 4; seq++ {
		if resp := rig.publish(t, control, "audit.ingest.control-plane", event(seq, "control")); resp.StatusCode != 200 {
			t.Fatalf("control seq %d: status %d", seq, resp.StatusCode)
		}
		if resp := rig.publish(t, objstore, "audit.ingest.object-store", event(seq, "objstore")); resp.StatusCode != 200 {
			t.Fatalf("objstore seq %d: status %d", seq, resp.StatusCode)
		}
	}

	// INV-2: control-plane peer publishing to the object-store channel is
	// rejected; nothing is admitted, chains stay unbroken.
	before := len(rig.store.Records())
	resp := rig.publish(t, control, "audit.ingest.object-store", event(99, "crosschannel"))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-channel publish should be 403, got %d", resp.StatusCode)
	}
	if after := len(rig.store.Records()); after != before {
		t.Fatalf("cross-channel publish admitted a record (%d -> %d)", before, after)
	}

	// Sign the daily head.
	pubHex := rig.signHead(t)
	pinnedPub, _ := hex.DecodeString(pubHex)

	// Independent verifier passes from genesis over the RAW WAL bytes.
	raw, err := store.ReadRawRecords(rig.walPath)
	if err != nil {
		t.Fatalf("read raw wal: %v", err)
	}
	if len(raw) != 8 {
		t.Fatalf("expected 8 committed records, got %d", len(raw))
	}
	headBytes, _ := os.ReadFile(rig.headPath)
	sh, _ := signer.UnmarshalSignedHead(headBytes)

	// Sample a MIDDLE record for the inclusion proof.
	sample := uint64(3)
	res, err := store.VerifyStore(raw, sh, pinnedPub, sample)
	if err != nil {
		t.Fatalf("keystone verify FAILED: %v", err)
	}
	t.Logf("keystone OK: %d records across %v; head=%s",
		res.RecordCount, res.Sources, hex.EncodeToString(res.Head))

	// TAMPER one byte in a middle WAL record -> verifier RED.
	tamperMiddleRecord(t, rig.walPath)
	rawT, err := store.ReadRawRecords(rig.walPath)
	if err != nil {
		// A CRC-level tamper is itself a RED (corrupt log) -> acceptable RED.
		t.Logf("tamper detected at WAL CRC layer: %v", err)
		return
	}
	if _, err := store.VerifyStore(rawT, sh, pinnedPub, sample); err == nil {
		t.Fatal("tampered WAL record must make the verifier RED")
	}
	t.Log("tamper -> verifier RED (as required)")
}

// tamperMiddleRecord flips a byte inside a middle record's actor_id value so the
// chain hash no longer recomputes, WITHOUT corrupting the JSON structure. It
// rewrites the WAL frames with fresh CRCs so the corruption is at the semantic
// (chain) layer, exercising the chain verifier rather than only the CRC.
func tamperMiddleRecord(t *testing.T, path string) {
	t.Helper()
	frames, err := wal.ReadAll(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) < 3 {
		t.Fatalf("need >=3 frames to tamper a middle one, got %d", len(frames))
	}
	mid := len(frames) / 2
	var rec map[string]json.RawMessage
	if err := json.Unmarshal(frames[mid], &rec); err != nil {
		t.Fatal(err)
	}
	rec["actor_id"] = json.RawMessage(`"tampered-actor"`)
	newFrame, _ := json.Marshal(rec)
	frames[mid] = newFrame
	rewriteWAL(t, path, frames)
}

// rewriteWAL rewrites the WAL file from a slice of frame payloads, re-framing
// each with a valid length+CRC so ReadAll accepts them (the tamper is at the
// record-content layer, not the framing layer).
func rewriteWAL(t *testing.T, path string, frames [][]byte) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	w, err := wal.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, fr := range frames {
		if err := w.Append(fr); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}
