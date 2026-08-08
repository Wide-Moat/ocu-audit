// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package wal

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// ADR-0045 stage 1: the audit store becomes an ordered segment set — one
// active append file plus sealed segments named in commit order. Sealing
// fsyncs, closes, atomically renames the active file, and reopens a fresh
// active at the same path. Chain linkage stays the ordering authority; the
// segment name order is a hint verification cross-checks.

func TestSegmentNamingRoundTrips(t *testing.T) {
	if got := SegmentName(1); got != "audit-000001.wal" {
		t.Fatalf("SegmentName(1) = %q, want audit-000001.wal", got)
	}
	if got := SegmentName(123456); got != "audit-123456.wal" {
		t.Fatalf("SegmentName(123456) = %q", got)
	}
}

func TestListSegmentsOrdersStrictly(t *testing.T) {
	dir := t.TempDir()
	// Created deliberately out of order; listing must sort by index.
	for _, n := range []string{"audit-000003.wal", "audit-000001.wal", "audit-000002.wal"} {
		if err := os.WriteFile(filepath.Join(dir, n), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Non-segment names are ignored, not errors.
	for _, n := range []string{"audit.wal", "audit-head.json", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(dir, n), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	segs, err := ListSegments(dir)
	if err != nil {
		t.Fatalf("ListSegments: %v", err)
	}
	want := []string{"audit-000001.wal", "audit-000002.wal", "audit-000003.wal"}
	if len(segs) != len(want) {
		t.Fatalf("ListSegments = %v, want %v", segs, want)
	}
	for i := range want {
		if filepath.Base(segs[i]) != want[i] {
			t.Fatalf("segment %d = %q, want %q", i, segs[i], want[i])
		}
	}
}

// TestListSegmentsRefusesAmbiguousIndex: two file names parsing to one index
// (differing padding) are an ambiguity about commit order — fail closed rather
// than pick one.
func TestListSegmentsRefusesAmbiguousIndex(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"audit-000007.wal", "audit-7.wal"} {
		if err := os.WriteFile(filepath.Join(dir, n), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ListSegments(dir); err == nil {
		t.Fatal("two names parsing to segment index 7 listed without error; " +
			"ambiguous commit order must fail closed")
	}
}

func TestSealToCreatesSegmentAndFreshActive(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "audit.wal")
	w, err := Open(active)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	if err := w.Append([]byte("record-A")); err != nil {
		t.Fatal(err)
	}
	sealed := filepath.Join(dir, SegmentName(1))
	if err := w.SealTo(sealed); err != nil {
		t.Fatalf("SealTo: %v", err)
	}
	if err := w.Append([]byte("record-B")); err != nil {
		t.Fatalf("append after seal: %v", err)
	}

	segFrames, err := ReadAll(sealed)
	if err != nil {
		t.Fatalf("read sealed: %v", err)
	}
	if len(segFrames) != 1 || string(segFrames[0]) != "record-A" {
		t.Fatalf("sealed segment holds %d frames (%q), want [record-A]", len(segFrames), segFrames)
	}
	actFrames, err := ReadAll(active)
	if err != nil {
		t.Fatalf("read active: %v", err)
	}
	if len(actFrames) != 1 || string(actFrames[0]) != "record-B" {
		t.Fatalf("fresh active holds %d frames (%q), want [record-B]", len(actFrames), actFrames)
	}
}

// TestSealToUnderConcurrentAppend: appends racing a seal lose nothing — every
// appended record lands intact in exactly one of (sealed segment, fresh
// active), and relative append order is preserved across the boundary.
func TestSealToUnderConcurrentAppend(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "audit.wal")
	w, err := Open(active)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	const n = 50
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			// Append never returns ErrClosed mid-seal: seal holds the same
			// mutex, so an append lands wholly before or wholly after.
			if err := w.Append([]byte{byte(i)}); err != nil {
				t.Errorf("append %d: %v", i, err)
				return
			}
		}
	}()
	sealed := filepath.Join(dir, SegmentName(1))
	if err := w.SealTo(sealed); err != nil {
		t.Fatalf("SealTo: %v", err)
	}
	wg.Wait()

	segFrames, err := ReadAll(sealed)
	if err != nil {
		t.Fatal(err)
	}
	actFrames, err := ReadAll(active)
	if err != nil {
		t.Fatal(err)
	}
	total := len(segFrames) + len(actFrames)
	if total != n {
		t.Fatalf("%d frames across sealed+active, want %d — a record was lost or duplicated by the seal", total, n)
	}
	// Order across the boundary: sealed frames then active frames must be
	// exactly 0..n-1.
	all := append(segFrames, actFrames...)
	for i, fr := range all {
		if len(fr) != 1 || fr[0] != byte(i) {
			t.Fatalf("frame %d = %v, want [%d] — append order broke across the seal boundary", i, fr, i)
		}
	}
}

// TestSealTwiceProducesOrderedSegments: repeated seals accumulate segments the
// listing returns in commit order.
func TestSealTwiceProducesOrderedSegments(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "audit.wal")
	w, err := Open(active)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	if err := w.Append([]byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := w.SealTo(filepath.Join(dir, SegmentName(1))); err != nil {
		t.Fatal(err)
	}
	if err := w.Append([]byte("two")); err != nil {
		t.Fatal(err)
	}
	if err := w.SealTo(filepath.Join(dir, SegmentName(2))); err != nil {
		t.Fatal(err)
	}
	segs, err := ListSegments(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 2 {
		t.Fatalf("%d segments after two seals, want 2", len(segs))
	}
	first, _ := ReadAll(segs[0])
	second, _ := ReadAll(segs[1])
	if len(first) != 1 || string(first[0]) != "one" || len(second) != 1 || string(second[0]) != "two" {
		t.Fatalf("segment contents [%q, %q], want [one], [two]", first, second)
	}
}
