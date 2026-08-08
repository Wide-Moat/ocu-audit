// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Wide-Moat/ocu-audit/internal/chain"
	"github.com/Wide-Moat/ocu-audit/internal/ocsf"
	"github.com/Wide-Moat/ocu-audit/internal/signer"
	"github.com/Wide-Moat/ocu-audit/internal/wal"
)

// seedWAL admits the given (source, seq) pairs into a fresh WAL at a temp
// path, closes it, and returns the path plus the pre-restart head and size.
// It models the process generation that dies before a restart.
func seedWAL(t *testing.T, pairs [][2]any) (string, []byte, uint64) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "recover.wal")
	w, err := wal.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	st := New(w, zeroClock{})
	for _, pr := range pairs {
		src, seq := pr[0].(string), pr[1].(uint64)
		if _, err := st.Admit(src, env(seq)); err != nil {
			t.Fatalf("seed admit %s/%d: %v", src, seq, err)
		}
	}
	head, size, err := st.Head()
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return p, head, size
}

// TestRecoverRestoresHeadAcrossRestart pins the restart contract: a recovered
// store serves the SAME head (root and tree size) the pre-restart process
// served, so a post-restart ticker can never overwrite a good head with a
// genesis one (the live 2026-07-16 failure mode).
func TestRecoverRestoresHeadAcrossRestart(t *testing.T) {
	p, wantHead, wantSize := seedWAL(t, [][2]any{
		{"control-plane", uint64(1)},
		{"control-plane", uint64(2)},
		{"control-plane", uint64(3)},
		{"object-store", uint64(1)},
	})

	st, err := Recover(p, zeroClock{})
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	gotHead, gotSize, err := st.Head()
	if err != nil {
		t.Fatalf("head after recover: %v", err)
	}
	if gotSize != wantSize {
		t.Fatalf("tree size after recover = %d, want %d", gotSize, wantSize)
	}
	if !bytes.Equal(gotHead, wantHead) {
		t.Fatalf("head after recover = %x, want %x", gotHead, wantHead)
	}
}

// TestAdmitAfterRecoverKeepsWholeWALVerifiable is the keystone test for the
// corruption mode this bug enables: an admit AFTER a restart must continue the
// per-source chain (never re-anchor on genesis), so the independent verifier
// stays GREEN over the WHOLE WAL — old records and new.
func TestAdmitAfterRecoverKeepsWholeWALVerifiable(t *testing.T) {
	// Seed with a sequence GAP (1 then 3): strictly-increasing admits allow
	// gaps, and the gap gives the dedupe/regression assertions below a seq (2)
	// that is below the recovered tip yet never seen.
	p, _, _ := seedWAL(t, [][2]any{
		{"control-plane", uint64(1)},
		{"control-plane", uint64(3)},
	})

	st, err := Recover(p, zeroClock{})
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	// Dedupe and sequence state must come from RECOVERY itself, so probe them
	// BEFORE any post-recovery admit (a successful admit would rebuild the
	// sequence tip as a side effect and mask a recovery that skipped it):
	if _, err := st.Admit("control-plane", env(2)); !errors.Is(err, ErrSequenceRegressed) {
		t.Fatalf("unseen below-tip seq 2 = %v, want ErrSequenceRegressed", err)
	}
	if _, err := st.Admit("control-plane", env(1)); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("replay of committed seq 1 = %v, want ErrDuplicate", err)
	}

	// New records after recovery: the existing source continues its chain, a
	// brand-new source opens its own.
	if _, err := st.Admit("control-plane", env(4)); err != nil {
		t.Fatalf("admit after recover (existing source): %v", err)
	}
	if _, err := st.Admit("object-store", env(1)); err != nil {
		t.Fatalf("admit after recover (new source): %v", err)
	}

	// The record list must be rebuilt too — Records() and the inclusion-proof
	// surface serve from it, and a head-only recovery would break both.
	if got := len(st.Records()); got != 4 {
		t.Fatalf("recovered store serves %d records, want 4", got)
	}
	if _, _, err := st.InclusionProof(0); err != nil {
		t.Fatalf("inclusion proof for record 0 after recovery: %v", err)
	}

	// Independent verification over the WHOLE WAL, exactly the wired path: raw
	// bytes reread from disk, head signed by the recovered store's signer.
	head, size, err := st.Head()
	if err != nil {
		t.Fatal(err)
	}
	sgn, err := signer.Generate()
	if err != nil {
		t.Fatal(err)
	}
	sh := sgn.Sign(signer.HeadEnvelope{Date: "2026-07-17", TreeSize: size, Head: head})

	records, err := ReadRawRecords(p)
	if err != nil {
		t.Fatalf("reread raw records: %v", err)
	}
	res, err := VerifyStore(records, sh, sgn.PublicKey(), 0)
	if err != nil {
		t.Fatalf("VerifyStore over the whole WAL after restart+admit: %v", err)
	}
	if res.RecordCount != 4 {
		t.Fatalf("verified %d records, want 4", res.RecordCount)
	}
}

// TestRecoverRefusesBrokenChain pins fail-closed boot: a well-framed,
// CRC-valid record whose PrevHash does not link to its predecessor must make
// recovery refuse to serve (this reuses the verifier's chain-link logic; a
// recovery that skips link verification would boot over a forged WAL).
func TestRecoverRefusesBrokenChain(t *testing.T) {
	p, _, _ := seedWAL(t, [][2]any{
		{"control-plane", uint64(1)},
		{"control-plane", uint64(2)},
	})

	// Append a chain-breaking record through the WAL layer itself: valid JSON,
	// valid CRC frame, self-consistent ChainHash — but anchored on genesis
	// instead of record 2's hash.
	w, err := wal.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	rec := &ocsf.Record{
		Source: "control-plane", Sequence: 3,
		TraceID: "t", SessionID: "s", ActorID: "a",
		Resource: "r", Action: "act", Outcome: ocsf.OutcomeSuccess,
		Payload: json.RawMessage(`{"forged":true}`),
	}
	chain.Author(rec, chain.GenesisPrevHash)
	frame, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(frame); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := Recover(p, zeroClock{}); err == nil {
		t.Fatal("recover over a broken chain must refuse to serve, got nil error")
	}
}

// TestRecoverRefusesCorruptWAL pins fail-closed boot on a bit-flip: a byte
// flipped inside a committed frame (CRC mismatch) must refuse recovery, never
// silently skip the record.
func TestRecoverRefusesCorruptWAL(t *testing.T) {
	p, _, _ := seedWAL(t, [][2]any{
		{"control-plane", uint64(1)},
		{"control-plane", uint64(2)},
	})

	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0xff
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Recover(p, zeroClock{}); err == nil {
		t.Fatal("recover over a corrupt WAL must refuse to serve, got nil error")
	}
}

// TestRecoverRefusesUnopenableWALPath pins the open-failure branch: a path
// whose directory does not exist can be neither read nor created, and Recover
// must surface that as an error, never serve a store with no WAL under it.
func TestRecoverRefusesUnopenableWALPath(t *testing.T) {
	p := filepath.Join(t.TempDir(), "no-such-dir", "x.wal")
	if _, err := Recover(p, zeroClock{}); err == nil {
		t.Fatal("recover on an uncreatable WAL path must error, got nil")
	}
}

// TestVerifyStoreRejectsCrossSourceReorder pins the mis-order guard: swapping
// two records of DIFFERENT sources preserves every per-source chain, so only
// the recomputed-head comparison can catch it. A verifier whose head equality
// is broken (the exact surviving-mutant shape in bytesEqualCT) would pass a
// reordered store; this test makes that mutant killable.
func TestVerifyStoreRejectsCrossSourceReorder(t *testing.T) {
	p, head, size := seedWAL(t, [][2]any{
		{"control-plane", uint64(1)},
		{"object-store", uint64(1)},
	})
	records, err := ReadRawRecords(p)
	if err != nil {
		t.Fatal(err)
	}
	sgn, err := signer.Generate()
	if err != nil {
		t.Fatal(err)
	}
	sh := sgn.Sign(signer.HeadEnvelope{Date: "2026-07-17", TreeSize: size, Head: head})

	// Sanity: the honest order verifies.
	if _, err := VerifyStore(records, sh, sgn.PublicKey(), 0); err != nil {
		t.Fatalf("honest order must verify: %v", err)
	}

	// Cross-source swap: same records, same tree size, chains still verify.
	records[0], records[1] = records[1], records[0]
	if _, err := VerifyStore(records, sh, sgn.PublicKey(), 0); err == nil {
		t.Fatal("cross-source reordered records must fail verification, got nil")
	}
}

// TestRecoverOnAbsentWALStartsEmpty pins first boot through the same single
// code path: no WAL file yet means an empty store that can admit from genesis.
func TestRecoverOnAbsentWALStartsEmpty(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fresh.wal")

	st, err := Recover(p, zeroClock{})
	if err != nil {
		t.Fatalf("recover on absent WAL: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if _, size, err := st.Head(); err != nil || size != 0 {
		t.Fatalf("fresh store head: size=%d err=%v, want size=0 err=nil", size, err)
	}
	if _, err := st.Admit("control-plane", env(1)); err != nil {
		t.Fatalf("first admit on fresh store: %v", err)
	}
}
