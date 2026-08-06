// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingest

import (
	"crypto/tls"
	"encoding/hex"
	"net/http"
	"os"
	"testing"

	"github.com/Wide-Moat/ocu-audit/internal/signer"
	"github.com/Wide-Moat/ocu-audit/internal/store"
)

// TestKeystoneTamperRestore covers the tamper->RED->restore->GREEN cycle
// explicitly: verify green, tamper a middle record and confirm RED, restore
// the original bytes and confirm GREEN again.
func TestKeystoneTamperRestore(t *testing.T) {
	rig := newKeystoneRig(t)
	control := rig.clientFor(t, "control-plane")
	for seq := uint64(1); seq <= 5; seq++ {
		if resp := rig.publish(t, control, "audit.ingest.control-plane", event(seq, "control")); resp.StatusCode != 200 {
			t.Fatalf("seq %d status %d", seq, resp.StatusCode)
		}
	}
	pubHex := rig.signHead(t)
	pinnedPub, _ := hex.DecodeString(pubHex)

	// Snapshot the original WAL bytes for restore.
	orig, err := os.ReadFile(rig.walPath)
	if err != nil {
		t.Fatal(err)
	}
	headBytes, _ := os.ReadFile(rig.headPath)
	sh, _ := signer.UnmarshalSignedHead(headBytes)

	// GREEN.
	raw, _ := store.ReadRawRecords(rig.walPath)
	if _, err := store.VerifyStore(raw, sh, pinnedPub, 2); err != nil {
		t.Fatalf("pre-tamper verify should be green: %v", err)
	}

	// TAMPER middle -> RED.
	tamperMiddleRecord(t, rig.walPath)
	rawT, err := store.ReadRawRecords(rig.walPath)
	if err == nil {
		if _, err := store.VerifyStore(rawT, sh, pinnedPub, 2); err == nil {
			t.Fatal("tamper must make verify RED")
		}
	}

	// RESTORE -> GREEN.
	if err := os.WriteFile(rig.walPath, orig, 0o600); err != nil {
		t.Fatal(err)
	}
	rawR, _ := store.ReadRawRecords(rig.walPath)
	if _, err := store.VerifyStore(rawR, sh, pinnedPub, 2); err != nil {
		t.Fatalf("post-restore verify should be green again: %v", err)
	}
}

// TestKeystoneFsyncFaultNo200 asserts that when the WAL fsync seam faults, the
// real HTTP ingest face returns a non-200 (no ack), so a source cannot treat
// the event as committed (INV-4).
func TestKeystoneFsyncFaultNo200(t *testing.T) {
	rig := newKeystoneRig(t)
	control := rig.clientFor(t, "control-plane")
	// Commit one good record first.
	if resp := rig.publish(t, control, "audit.ingest.control-plane", event(1, "control")); resp.StatusCode != 200 {
		t.Fatalf("baseline status %d", resp.StatusCode)
	}
	// Inject the fault via the store's WAL. The store holds the WAL; reach it
	// through the same object the rig created.
	faultRigWAL(t, rig)
	resp := rig.publish(t, control, "audit.ingest.control-plane", event(2, "control"))
	if resp.StatusCode == 200 {
		t.Fatalf("fsync fault must NOT return 200 (INV-4); got %d", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Logf("fsync fault returned %d (any non-200 is acceptable)", resp.StatusCode)
	}
}

// TestKeystoneSequenceRegressionOverHTTP asserts a regressed sequence over the
// real face is 409 and admits nothing.
func TestKeystoneSequenceRegressionOverHTTP(t *testing.T) {
	rig := newKeystoneRig(t)
	control := rig.clientFor(t, "control-plane")
	if resp := rig.publish(t, control, "audit.ingest.control-plane", event(5, "control")); resp.StatusCode != 200 {
		t.Fatalf("seq 5 status %d", resp.StatusCode)
	}
	before := len(rig.store.Records())
	resp := rig.publish(t, control, "audit.ingest.control-plane", event(3, "control"))
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("regressed sequence should be 409, got %d", resp.StatusCode)
	}
	if after := len(rig.store.Records()); after != before {
		t.Fatalf("regressed sequence admitted a record (%d -> %d)", before, after)
	}
}

// TestKeystoneNoClientCertRejected asserts a publish with no client certificate
// is rejected (401): the source binding is host-attested, never anonymous.
func TestKeystoneNoClientCertRejected(t *testing.T) {
	rig := newKeystoneRig(t)
	// A plain client with the CA root but NO client certificate. The mTLS
	// server requires a verified client cert, so the TLS handshake itself is
	// refused; a transport error (not a 200) is the correct outcome.
	noCert := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: rig.ca.pool, MinVersion: tls.VersionTLS13},
	}}
	resp, err := noCert.Post(rig.srv.URL+"/v1alpha/audit/audit.ingest.control-plane",
		"application/json", nil)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			t.Fatal("publish without a client certificate must not return 200")
		}
		return
	}
	// A handshake-level rejection is the expected path.
	t.Logf("no-client-cert publish rejected at TLS layer: %v", err)
}

// faultRigWAL swaps the rig store's WAL syncer to a faulting one via the
// store's test-only fault seam.
func faultRigWAL(t *testing.T, rig *keystoneRig) {
	t.Helper()
	store.FaultWALForTest(rig.store, faultSyncerLeg{})
}

type faultSyncerLeg struct{}

func (faultSyncerLeg) Sync() error { return errFaultLeg }

var errFaultLeg = os.ErrDeadlineExceeded
