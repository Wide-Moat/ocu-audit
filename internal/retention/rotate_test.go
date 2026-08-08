// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package retention

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-audit/internal/wal"
)

// The crash matrix asserts ON-DISK POSTCONDITIONS at every abort point — the
// hot copy present and intact, or a complete verified cold copy; never
// neither — not merely "Rotate returned an error". The fault seam wraps the
// real filesystem, so the state each "crash" leaves is the authentic one.

// faultFS wraps osFS and fails the Nth seam call (1-based), modelling a crash
// at exactly that step.
type faultFS struct {
	osFS
	failAt int
	calls  int
	// corruptTemp flips a byte in the temp AFTER the durable write, modelling
	// media corruption between write and verify.
	corruptTemp bool
}

var errInjected = errors.New("injected fault")

func (f *faultFS) step() error {
	f.calls++
	if f.calls == f.failAt {
		return errInjected
	}
	return nil
}

func (f *faultFS) ReadFile(path string) ([]byte, error) {
	if err := f.step(); err != nil {
		return nil, err
	}
	return f.osFS.ReadFile(path)
}

func (f *faultFS) WriteTemp(dir, pattern string, data []byte) (string, error) {
	if err := f.step(); err != nil {
		return "", err
	}
	name, err := f.osFS.WriteTemp(dir, pattern, data)
	if err == nil && f.corruptTemp {
		raw, rerr := os.ReadFile(name)
		if rerr != nil {
			return name, rerr
		}
		corruptFrameCRCNeutral(raw)
		if werr := os.WriteFile(name, raw, 0o600); werr != nil {
			return name, werr
		}
	}
	return name, err
}

// corruptFrameCRCNeutral flips one payload byte of the FIRST frame and
// recomputes that frame's CRC32, so the corruption is invisible to the frame
// reader and ONLY the whole-file digest can catch it. A frame-CRC-visible
// corruption would let a neighboring CRC check mask the digest check.
func corruptFrameCRCNeutral(raw []byte) {
	length := binary.BigEndian.Uint32(raw[0:4])
	payload := raw[8 : 8+length]
	payload[0] ^= 0x01
	binary.BigEndian.PutUint32(raw[4:8], crc32.ChecksumIEEE(payload))
}

func (f *faultFS) SyncDir(dir string) error {
	if err := f.step(); err != nil {
		return err
	}
	return f.osFS.SyncDir(dir)
}

func (f *faultFS) Rename(oldPath, newPath string) error {
	if err := f.step(); err != nil {
		return err
	}
	return f.osFS.Rename(oldPath, newPath)
}

func (f *faultFS) Remove(path string) error {
	if err := f.step(); err != nil {
		return err
	}
	return f.osFS.Remove(path)
}

// sealedSegment writes a real WAL segment with n records and returns its path
// and bytes.
func sealedSegment(t *testing.T, dir string, n int) (string, []byte) {
	t.Helper()
	active := filepath.Join(dir, "audit.wal")
	w, err := wal.Open(active)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if err := w.Append([]byte{byte(i), byte(i + 1)}); err != nil {
			t.Fatal(err)
		}
	}
	seg := filepath.Join(dir, wal.SegmentName(1))
	if err := w.SealTo(seg); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(seg)
	if err != nil {
		t.Fatal(err)
	}
	return seg, raw
}

// TestRotateHappyPath: cold holds the verified copy under the final name, hot
// copy gone, no temporaries left.
func TestRotateHappyPath(t *testing.T) {
	hotDir, coldDir := t.TempDir(), t.TempDir()
	seg, want := sealedSegment(t, hotDir, 3)

	if err := Rotate(osFS{}, seg, coldDir); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	coldBytes, err := os.ReadFile(filepath.Join(coldDir, filepath.Base(seg)))
	if err != nil {
		t.Fatalf("cold copy missing: %v", err)
	}
	if !bytes.Equal(coldBytes, want) {
		t.Fatal("cold copy differs from the sealed hot bytes")
	}
	if _, err := os.Stat(seg); !os.IsNotExist(err) {
		t.Fatal("hot copy still present after a verified rotation")
	}
	tmps, _ := filepath.Glob(filepath.Join(coldDir, ".rotate-*"))
	if len(tmps) != 0 {
		t.Fatalf("temporaries left after a clean rotation: %v", tmps)
	}
}

// TestRotateCrashMatrix aborts at EVERY seam call and asserts the on-disk
// postcondition, then proves resume + retry completes to the exact happy-path
// end state with zero byte drift.
func TestRotateCrashMatrix(t *testing.T) {
	// Walk fail points until a run completes without hitting one.
	for failAt := 1; ; failAt++ {
		hotDir, coldDir := t.TempDir(), t.TempDir()
		seg, want := sealedSegment(t, hotDir, 3)
		fs := &faultFS{failAt: failAt}

		err := Rotate(fs, seg, coldDir)
		if err == nil {
			if failAt < 3 {
				t.Fatalf("rotation completed before any fault point was reached (failAt=%d)", failAt)
			}
			break // matrix exhausted: the happy path has fewer calls than failAt
		}
		if !errors.Is(err, errInjected) {
			t.Fatalf("failAt=%d: unexpected error class: %v", failAt, err)
		}

		// POSTCONDITION at every crash: the hot copy is intact OR the final
		// cold copy is complete and byte-identical. Never neither.
		hotBytes, hotErr := os.ReadFile(seg)
		coldBytes, coldErr := os.ReadFile(filepath.Join(coldDir, filepath.Base(seg)))
		hotIntact := hotErr == nil && bytes.Equal(hotBytes, want)
		coldComplete := coldErr == nil && bytes.Equal(coldBytes, want)
		if !hotIntact && !coldComplete {
			t.Fatalf("failAt=%d: crash left NEITHER an intact hot copy nor a complete cold copy — a committed record is lost", failAt)
		}

		// Resume + retry with no faults must converge to the rotated state.
		if err := Rotate(osFS{}, seg, coldDir); err != nil {
			t.Fatalf("failAt=%d: retry after crash: %v", failAt, err)
		}
		finalBytes, err := os.ReadFile(filepath.Join(coldDir, filepath.Base(seg)))
		if err != nil || !bytes.Equal(finalBytes, want) {
			t.Fatalf("failAt=%d: post-retry cold copy wrong: %v", failAt, err)
		}
		if _, err := os.Stat(seg); !os.IsNotExist(err) {
			t.Fatalf("failAt=%d: hot copy still present after the retry completed", failAt)
		}
	}
}

// TestRotateAbortsOnCorruptedColdTemp: media corruption between the durable
// temp write and the verify re-read must abort with the hot copy intact and
// no final-name cold file — the verify MUST read from disk, not the buffer.
func TestRotateAbortsOnCorruptedColdTemp(t *testing.T) {
	hotDir, coldDir := t.TempDir(), t.TempDir()
	seg, want := sealedSegment(t, hotDir, 3)

	err := Rotate(&faultFS{corruptTemp: true}, seg, coldDir)
	if err == nil {
		t.Fatal("rotation succeeded over a corrupted cold copy; the verify compared " +
			"the in-memory buffer, not the disk")
	}
	hotBytes, herr := os.ReadFile(seg)
	if herr != nil || !bytes.Equal(hotBytes, want) {
		t.Fatal("hot copy not intact after an aborted rotation")
	}
	if _, err := os.Stat(filepath.Join(coldDir, filepath.Base(seg))); !os.IsNotExist(err) {
		t.Fatal("a corrupted copy reached the FINAL cold name")
	}
}

// TestResumeDivergentCopiesRefusesWithBothIntact: a complete cold file that
// differs from the surviving hot copy is a tamper signal. The refusal must
// carry the DIVERGENCE diagnostic (not a CRC or chain message some later
// check would also produce) and leave BOTH files untouched as evidence.
func TestResumeDivergentCopiesRefusesWithBothIntact(t *testing.T) {
	hotDir, coldDir := t.TempDir(), t.TempDir()
	seg, hotWant := sealedSegment(t, hotDir, 3)

	// A complete, WELL-FRAMED cold segment with different content: built from
	// a different record set, so only the byte-compare can catch it.
	otherDir := t.TempDir()
	otherSeg, _ := sealedSegment(t, otherDir, 2)
	otherBytes, err := os.ReadFile(otherSeg)
	if err != nil {
		t.Fatal(err)
	}
	finalPath := filepath.Join(coldDir, filepath.Base(seg))
	if err := os.WriteFile(finalPath, otherBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	err = Rotate(osFS{}, seg, coldDir)
	if err == nil {
		t.Fatal("rotation resolved divergent hot/cold copies silently")
	}
	if !errors.Is(err, ErrDivergentCopies) {
		t.Fatalf("divergence refusal error = %v, want ErrDivergentCopies — the refusal "+
			"must be the divergence check's own, not a downstream CRC/chain message", err)
	}
	if !strings.Contains(err.Error(), filepath.Base(seg)) {
		t.Fatalf("divergence diagnostic %q does not name the segment", err)
	}
	// Both files stay as evidence.
	gotHot, err := os.ReadFile(seg)
	if err != nil || !bytes.Equal(gotHot, hotWant) {
		t.Fatal("the hot copy was altered by a refused resume")
	}
	gotCold, err := os.ReadFile(finalPath)
	if err != nil || !bytes.Equal(gotCold, otherBytes) {
		t.Fatal("the cold copy was altered by a refused resume")
	}
}

// TestResumeIdenticalCopiesFinishesRemoval: identical complete copies are a
// crash after rename, before removal — resume finishes the removal.
func TestResumeIdenticalCopiesFinishesRemoval(t *testing.T) {
	hotDir, coldDir := t.TempDir(), t.TempDir()
	seg, want := sealedSegment(t, hotDir, 3)
	if err := copySegFile(seg, filepath.Join(coldDir, filepath.Base(seg))); err != nil {
		t.Fatal(err)
	}

	if err := Rotate(osFS{}, seg, coldDir); err != nil {
		t.Fatalf("resume over identical copies: %v", err)
	}
	if _, err := os.Stat(seg); !os.IsNotExist(err) {
		t.Fatal("hot copy still present; resume did not finish the removal")
	}
	coldBytes, err := os.ReadFile(filepath.Join(coldDir, filepath.Base(seg)))
	if err != nil || !bytes.Equal(coldBytes, want) {
		t.Fatal("cold copy wrong after resume")
	}
}

// TestRotateRefusesCorruptHotSegment: a hot segment with a flipped interior
// byte (CRC re-fixed NOT applied — the frame CRC catches it) must refuse to
// rotate, so corruption is never laundered into the cold tier.
func TestRotateRefusesCorruptHotSegment(t *testing.T) {
	hotDir, coldDir := t.TempDir(), t.TempDir()
	seg, _ := sealedSegment(t, hotDir, 3)
	raw, err := os.ReadFile(seg)
	if err != nil {
		t.Fatal(err)
	}
	raw[9] ^= 0x01 // inside the first frame's payload
	if err := os.WriteFile(seg, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Rotate(osFS{}, seg, coldDir); err == nil {
		t.Fatal("a corrupt hot segment rotated; corruption was laundered into the cold tier")
	}
	if _, err := os.Stat(filepath.Join(coldDir, filepath.Base(seg))); !os.IsNotExist(err) {
		t.Fatal("a corrupt segment reached a final cold name")
	}
}

// copySegFile duplicates a segment file byte-for-byte.
func copySegFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o600)
}
