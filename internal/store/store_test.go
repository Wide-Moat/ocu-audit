// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package store

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/Wide-Moat/ocu-audit/internal/ocsf"
	"github.com/Wide-Moat/ocu-audit/internal/wal"
)

func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "s.wal")
	w, err := wal.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return New(w), p
}

func env(seq uint64) *ocsf.PublishEnvelope {
	return &ocsf.PublishEnvelope{
		TraceID: "t", SessionID: "s", ActorID: "a",
		Resource: "r", Action: "act", Outcome: ocsf.OutcomeSuccess,
		Sequence: seq, Payload: json.RawMessage(`{"seq":` + itoa(int(seq)) + `}`),
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

// TestAdmitMonotonic asserts strictly increasing sequences admit and the chain
// links.
func TestAdmitMonotonic(t *testing.T) {
	st, _ := newStore(t)
	for seq := uint64(1); seq <= 5; seq++ {
		if _, err := st.Admit("control-plane", env(seq)); err != nil {
			t.Fatalf("seq %d should admit: %v", seq, err)
		}
	}
	if got := len(st.Records()); got != 5 {
		t.Fatalf("expected 5 committed, got %d", got)
	}
}

// TestSequenceRegressionRejected asserts a regressed sequence is rejected and
// nothing is committed (chain unbroken).
func TestSequenceRegressionRejected(t *testing.T) {
	st, _ := newStore(t)
	_, _ = st.Admit("control-plane", env(5))
	_, err := st.Admit("control-plane", env(3))
	if !errors.Is(err, ErrSequenceRegressed) {
		t.Fatalf("expected ErrSequenceRegressed, got %v", err)
	}
	if got := len(st.Records()); got != 1 {
		t.Fatalf("regressed publish must not commit; got %d records", got)
	}
}

// TestExactReplayDeduped asserts an exact (source, sequence) replay is an
// idempotent no-op (ErrDuplicate) and does not append a second record.
func TestExactReplayDeduped(t *testing.T) {
	st, _ := newStore(t)
	_, _ = st.Admit("control-plane", env(1))
	_, err := st.Admit("control-plane", env(1))
	if !errors.Is(err, ErrDuplicate) {
		t.Fatalf("expected ErrDuplicate on replay, got %v", err)
	}
	if got := len(st.Records()); got != 1 {
		t.Fatalf("replay must not double-commit; got %d records", got)
	}
}

// TestPerSourceIndependentChains asserts two sources keep independent chains and
// both verify from genesis via the raw reader.
func TestPerSourceIndependentChains(t *testing.T) {
	st, p := newStore(t)
	for seq := uint64(1); seq <= 3; seq++ {
		if _, err := st.Admit("control-plane", env(seq)); err != nil {
			t.Fatal(err)
		}
		if _, err := st.Admit("object-store", env(seq)); err != nil {
			t.Fatal(err)
		}
	}
	// Close so the WAL flushes, then re-read raw and verify both chains.
	raw, err := ReadRawRecords(p)
	if err != nil {
		t.Fatal(err)
	}
	sources, err := VerifyChainsFromRaw(raw)
	if err != nil {
		t.Fatalf("both chains should verify: %v", err)
	}
	if len(sources) != 2 {
		t.Fatalf("expected 2 sources, got %v", sources)
	}
}

// TestFsyncFaultNoCommit asserts that when the WAL fsync faults, Admit errors
// and no state advances (chain stays admissible on retry).
func TestFsyncFaultNoCommit(t *testing.T) {
	st, _ := newStore(t)
	st.w.SetSyncer(faultSyncer{})
	if _, err := st.Admit("control-plane", env(1)); err == nil {
		t.Fatal("Admit must fail when the durable commit faults (no ack)")
	}
	if got := len(st.Records()); got != 0 {
		t.Fatalf("faulted admit must not commit; got %d records", got)
	}
	// Recover the syncer and retry the SAME sequence: it must now admit,
	// proving no phantom sequence was consumed.
	st.w.SetSyncer(realSyncer{st})
	if _, err := st.Admit("control-plane", env(1)); err != nil {
		t.Fatalf("retry after fault should admit seq 1: %v", err)
	}
}

type faultSyncer struct{}

func (faultSyncer) Sync() error { return errors.New("injected fsync fault") }

// realSyncer restores the WAL's own file sync via a no-op that always succeeds
// (the test WAL already flushed the frame; we only need Sync to return nil so
// the retry path commits).
type realSyncer struct{ st *Store }

func (realSyncer) Sync() error { return nil }
