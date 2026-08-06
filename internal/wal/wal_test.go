// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package wal

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func tmpWAL(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "test.wal")
}

// TestAppendReadRoundTrip asserts framed records read back in order.
func TestAppendReadRoundTrip(t *testing.T) {
	p := tmpWAL(t)
	w, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	payloads := [][]byte{[]byte("alpha"), []byte("bravo"), []byte("charlie")}
	for _, pl := range payloads {
		if err := w.Append(pl); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := ReadAll(p)
	if err != nil {
		t.Fatalf("readall: %v", err)
	}
	if len(got) != len(payloads) {
		t.Fatalf("got %d records, want %d", len(got), len(payloads))
	}
	for i := range got {
		if string(got[i]) != string(payloads[i]) {
			t.Fatalf("record %d = %q, want %q", i, got[i], payloads[i])
		}
	}
}

// faultSyncer fails Sync, simulating an fsync fault.
type faultSyncer struct{}

func (faultSyncer) Sync() error { return errors.New("injected fsync fault") }

// TestFsyncFaultRefusesAck asserts Append returns an error when the fsync seam
// faults: this is the "no 200" refusal (INV-4). The caller must not ack.
func TestFsyncFaultRefusesAck(t *testing.T) {
	p := tmpWAL(t)
	w, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	w.SetSyncer(faultSyncer{})
	if err := w.Append([]byte("must-not-ack")); err == nil {
		t.Fatal("Append must return an error on fsync fault (no ack, INV-4)")
	}
}

// TestReadAllDropsTornTrailer asserts a truncated trailing frame is dropped,
// not surfaced as a record and not an error (a crash mid-append leaves a torn
// tail; the committed prefix is intact).
func TestReadAllDropsTornTrailer(t *testing.T) {
	p := tmpWAL(t)
	w, _ := Open(p)
	_ = w.Append([]byte("committed"))
	_ = w.Close()
	// Append a torn frame: a header claiming 100 bytes, but only 3 follow.
	f, _ := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0o600)
	f.Write([]byte{0, 0, 0, 100, 0, 0, 0, 0, 'a', 'b', 'c'})
	f.Close()
	got, err := ReadAll(p)
	if err != nil {
		t.Fatalf("torn trailer must not error, got %v", err)
	}
	if len(got) != 1 || string(got[0]) != "committed" {
		t.Fatalf("expected only the committed record, got %v", got)
	}
}

// TestReadAllDetectsCRCTamper asserts a bit-flip in a middle record's payload
// is caught by the CRC check as a hard error.
func TestReadAllDetectsCRCTamper(t *testing.T) {
	p := tmpWAL(t)
	w, _ := Open(p)
	_ = w.Append([]byte("aaaa"))
	_ = w.Append([]byte("bbbb"))
	_ = w.Close()
	raw, _ := os.ReadFile(p)
	// Flip a byte in the first record's payload (offset 8 = after first header).
	raw[8] ^= 0xff
	_ = os.WriteFile(p, raw, 0o600)
	if _, err := ReadAll(p); err == nil {
		t.Fatal("CRC mismatch on a middle record must be a hard error")
	}
}
