// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package store

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Wide-Moat/ocu-audit/internal/ocsf"
	"github.com/Wide-Moat/ocu-audit/internal/signer"
	"github.com/Wide-Moat/ocu-audit/internal/wal"
)

// TestEmitVerifierFixture writes a real WAL + signed head + pinned pubkey to the
// directory named by OCU_AUDIT_FIXTURE_DIR (when set) so the ocu-audit-verify
// binary can be run against genuine on-disk bytes in a shell harness. It is a
// no-op unless the env var is set, so it never runs in normal CI.
func TestEmitVerifierFixture(t *testing.T) {
	dir := os.Getenv("OCU_AUDIT_FIXTURE_DIR")
	if dir == "" {
		t.Skip("OCU_AUDIT_FIXTURE_DIR not set; skipping fixture emit")
	}
	walPath := filepath.Join(dir, "audit.wal")
	w, err := wal.Open(walPath)
	if err != nil {
		t.Fatal(err)
	}
	st := New(w)
	// Two sources, interleaved, into two chains.
	for seq := uint64(1); seq <= 4; seq++ {
		for _, src := range []string{"control-plane", "object-store"} {
			e := &ocsf.PublishEnvelope{
				TraceID: "t-" + src, SessionID: "s-" + src, ActorID: "a-" + src,
				Resource: "r", Action: "act", Outcome: ocsf.OutcomeSuccess,
				Sequence: seq, Payload: json.RawMessage(`{"src":"` + src + `","seq":` + itoa(int(seq)) + `}`),
			}
			if _, err := st.Admit(src, e); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	head, size, err := st.Head()
	if err != nil {
		t.Fatal(err)
	}
	sgn, _ := signer.Generate()
	sh := sgn.Sign(signer.HeadEnvelope{Date: "2026-07-16", TreeSize: size, Head: head})
	shBytes, _ := signer.MarshalSignedHead(sh)
	if err := os.WriteFile(filepath.Join(dir, "audit-head.json"), shBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pubkey.hex"),
		[]byte(hex.EncodeToString(sgn.PublicKey())), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("emitted fixture: %d records, head=%s", size, hex.EncodeToString(head))
}
