// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package store

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/Wide-Moat/ocu-audit/internal/wal"
)

// ADR-0045 stage 1: the hot tier is sealed segments plus the active file, and
// recovery reads them as one commit-ordered union — cumulative genesis
// verification is unchanged, only the file layout grew. (Rotation to cold and
// the signed checkpoint are the next stage.)

// TestRecoverReadsSealedSegmentsThenActive is the stage keystone: records
// admitted across two seals and a restart come back as ONE commit-ordered,
// genesis-verified set, and the recovered head equals the pre-restart head.
func TestRecoverReadsSealedSegmentsThenActive(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "audit.wal")

	w, err := wal.Open(active)
	if err != nil {
		t.Fatal(err)
	}
	gen1 := New(w, zeroClock{})
	// Two interleaved sources across two seal boundaries, so per-source chains
	// SPAN segments — a recovery that dropped or reordered a segment breaks
	// linkage, not just a count.
	admit := func(src string, seq uint64) {
		t.Helper()
		if _, err := gen1.Admit(src, env(seq)); err != nil {
			t.Fatalf("admit %s/%d: %v", src, seq, err)
		}
	}
	admit("control-plane", 1)
	admit("object-store", 1)
	if err := w.SealTo(filepath.Join(dir, wal.SegmentName(1))); err != nil {
		t.Fatalf("seal 1: %v", err)
	}
	admit("control-plane", 2)
	admit("object-store", 2)
	if err := w.SealTo(filepath.Join(dir, wal.SegmentName(2))); err != nil {
		t.Fatalf("seal 2: %v", err)
	}
	admit("control-plane", 3)

	wantHead, wantSize, err := gen1.Head()
	if err != nil {
		t.Fatal(err)
	}
	if err := gen1.Close(); err != nil {
		t.Fatal(err)
	}

	gen2, err := Recover(active, zeroClock{})
	if err != nil {
		t.Fatalf("recover over segments: %v", err)
	}
	t.Cleanup(func() { _ = gen2.Close() })

	recs := gen2.Records()
	if len(recs) != 5 {
		t.Fatalf("recovered %d records, want 5 — a sealed segment was skipped or double-read", len(recs))
	}
	// Commit order across the boundaries.
	wantOrder := []struct {
		src string
		seq uint64
	}{
		{"control-plane", 1}, {"object-store", 1},
		{"control-plane", 2}, {"object-store", 2},
		{"control-plane", 3},
	}
	for i, wo := range wantOrder {
		if recs[i].Source != wo.src || recs[i].Sequence != wo.seq {
			t.Fatalf("record %d = %s/%d, want %s/%d — commit order broke across a seal boundary",
				i, recs[i].Source, recs[i].Sequence, wo.src, wo.seq)
		}
	}
	gotHead, gotSize, err := gen2.Head()
	if err != nil {
		t.Fatal(err)
	}
	if gotSize != wantSize || !bytes.Equal(gotHead, wantHead) {
		t.Fatalf("recovered head (%x, %d) != pre-restart head (%x, %d)", gotHead, gotSize, wantHead, wantSize)
	}
	// A post-restart admit continues the chain across the whole union.
	if _, err := gen2.Admit("object-store", env(3)); err != nil {
		t.Fatalf("post-recover admit: %v", err)
	}
	if _, err := VerifyChainsFromRaw(gen2.Records()); err != nil {
		t.Fatalf("chains do not verify from genesis over segments+active after a fresh admit: %v", err)
	}
}

// TestSealActiveSnapshotsCommitState pins the store-level seal: it delegates
// to the WAL under the store lock and reports the commit count and tree size
// at the seal point (the checkpoint anchors the next stage records).
func TestSealActiveSnapshotsCommitState(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "audit.wal")
	w, err := wal.Open(active)
	if err != nil {
		t.Fatal(err)
	}
	st := New(w, zeroClock{})
	t.Cleanup(func() { _ = st.Close() })

	for seq := uint64(1); seq <= 3; seq++ {
		if _, err := st.Admit("control-plane", env(seq)); err != nil {
			t.Fatal(err)
		}
	}
	count, size, err := st.SealActive(filepath.Join(dir, wal.SegmentName(1)))
	if err != nil {
		t.Fatalf("SealActive: %v", err)
	}
	if count != 3 || size != 3 {
		t.Fatalf("SealActive snapshot (count=%d, size=%d), want (3, 3)", count, size)
	}
	// The seal is real: the segment file holds the three records and the
	// active file starts empty.
	segFrames, err := wal.ReadAll(filepath.Join(dir, wal.SegmentName(1)))
	if err != nil {
		t.Fatal(err)
	}
	if len(segFrames) != 3 {
		t.Fatalf("sealed segment holds %d frames, want 3", len(segFrames))
	}
	actFrames, err := wal.ReadAll(active)
	if err != nil {
		t.Fatal(err)
	}
	if len(actFrames) != 0 {
		t.Fatalf("active file holds %d frames after seal, want 0", len(actFrames))
	}
}

// TestRecoverRefusesAmbiguousSegments keeps the fail-closed listing: two names
// claiming one segment index refuse recovery rather than pick an order.
func TestRecoverRefusesAmbiguousSegments(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "audit.wal")
	w, err := wal.Open(active)
	if err != nil {
		t.Fatal(err)
	}
	st := New(w, zeroClock{})
	if _, err := st.Admit("control-plane", env(1)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.SealActive(filepath.Join(dir, wal.SegmentName(7))); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	// A second name parsing to index 7.
	if err := copyFile(filepath.Join(dir, wal.SegmentName(7)), filepath.Join(dir, "audit-7.wal")); err != nil {
		t.Fatal(err)
	}
	if _, err := Recover(active, zeroClock{}); err == nil {
		t.Fatal("recovery proceeded with two files claiming segment index 7; " +
			"ambiguous commit order must refuse boot")
	}
}

// copyFile duplicates a file byte-for-byte (test fixture helper).
func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o600)
}
