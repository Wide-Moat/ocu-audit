// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package retention

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Wide-Moat/ocu-audit/internal/wal"
)

// Rotation moves a sealed segment hot -> cold as copy-verify-rename
// (ADR-0045): copy to an ATTEMPT-UNIQUE temporary in the cold directory,
// fsync, re-read the cold bytes from disk and verify digest and frame
// checksums, atomically rename to the final segment name, fsync, and only
// then remove the hot copy. A crash at any step leaves the hot copy intact or
// a complete verified cold copy — never neither. A torn temporary is
// discarded on resume, never treated as divergent; under a WORM mount an
// orphaned temporary stays object-locked but inert (attempt-unique name,
// outside every inventory).

// ErrDivergentCopies reports a COMPLETE cold segment whose bytes differ from
// the surviving hot copy — a tamper signal, refused loudly, never resolved by
// silently picking a side.
var ErrDivergentCopies = errors.New("retention: hot and cold copies of a rotated segment diverge")

// rotateFS is the filesystem seam, the wal.Syncer pattern: production uses
// osFS; tests wrap it to inject a fault at one call, which models a crash at
// exactly that step with the real on-disk state left behind.
type rotateFS interface {
	ReadFile(path string) ([]byte, error)
	// WriteTemp creates an attempt-unique temp file in dir matching pattern,
	// writes data, fsyncs, and returns its path.
	WriteTemp(dir, pattern string, data []byte) (string, error)
	SyncDir(dir string) error
	Rename(oldPath, newPath string) error
	Remove(path string) error
}

// osFS is the production filesystem.
type osFS struct{}

func (osFS) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path) // #nosec G304 -- operator-configured tier paths
}

func (osFS) WriteTemp(dir, pattern string, data []byte) (string, error) {
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", err
	}
	name := f.Name()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return name, err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return name, err
	}
	return name, f.Close()
}

func (osFS) SyncDir(dir string) error             { return syncDir(dir) }
func (osFS) Rename(oldPath, newPath string) error { return os.Rename(oldPath, newPath) }
func (osFS) Remove(path string) error             { return os.Remove(path) }

// tempPattern returns the attempt-unique temp-name pattern for a segment.
// The leading dot keeps it outside the segment listing; CreateTemp's random
// suffix makes each attempt unique, so a WORM-locked orphan from a crashed
// attempt never blocks the next one.
func tempPattern(segName string) string { return ".rotate-" + segName + "-*" }

// Rotate copies the sealed hot segment at hotPath into coldDir under the same
// name, verified, then removes the hot copy. It is safe to re-run after any
// crash: ResumeSegment first reconciles whatever a previous attempt left.
func Rotate(fs rotateFS, hotPath, coldDir string) error {
	segName := filepath.Base(hotPath)
	if err := ResumeSegment(fs, hotPath, coldDir); err != nil {
		return err
	}
	if _, err := os.Stat(hotPath); errors.Is(err, os.ErrNotExist) {
		return nil // resume finished the rotation
	}

	hotBytes, err := fs.ReadFile(hotPath)
	if err != nil {
		return fmt.Errorf("retention: read hot segment: %w", err)
	}
	// Refuse to rotate a corrupt segment: frame CRCs must hold BEFORE the
	// copy, or rotation would launder corruption into the cold tier.
	if err := verifyFrames(hotPath); err != nil {
		return fmt.Errorf("retention: hot segment %s failed frame verification, not rotating: %w", segName, err)
	}

	tmpPath, err := fs.WriteTemp(coldDir, tempPattern(segName), hotBytes)
	if err != nil {
		return fmt.Errorf("retention: write cold temp: %w", err)
	}
	if err := fs.SyncDir(coldDir); err != nil {
		return err
	}
	// Verify the DURABLE cold bytes with a fresh read from disk — comparing
	// against the in-memory buffer would pass a copy the media corrupted. The
	// digest against the already-frame-verified hot bytes subsumes a frame
	// re-check on the temp: any cold divergence, CRC-visible or not, mismatches
	// the digest.
	coldBytes, err := fs.ReadFile(tmpPath)
	if err != nil {
		return fmt.Errorf("retention: re-read cold temp: %w", err)
	}
	if sha256.Sum256(coldBytes) != sha256.Sum256(hotBytes) {
		return fmt.Errorf("retention: cold copy of %s does not match the hot bytes after write; aborting with the hot copy intact", segName)
	}

	finalPath := filepath.Join(coldDir, segName)
	if err := fs.Rename(tmpPath, finalPath); err != nil {
		return fmt.Errorf("retention: rename cold temp to final: %w", err)
	}
	if err := fs.SyncDir(coldDir); err != nil {
		return err
	}
	if err := fs.Remove(hotPath); err != nil {
		return fmt.Errorf("retention: remove hot copy after verified rotation: %w", err)
	}
	return fs.SyncDir(filepath.Dir(hotPath))
}

// ResumeSegment reconciles the on-disk state a crashed rotation attempt left
// for one segment, idempotently:
//
//   - final cold + hot both present: byte-compare (fresh reads). Identical ->
//     finish the removal; divergent -> ErrDivergentCopies, BOTH files left
//     untouched (a tamper investigation needs the evidence).
//   - final cold present, hot gone: rotation already complete.
//   - temporaries present: discarded — torn or complete-but-unrenamed alike;
//     the copy redoes from the hot bytes.
func ResumeSegment(fs rotateFS, hotPath, coldDir string) error {
	segName := filepath.Base(hotPath)

	// Discard temporaries from crashed attempts.
	tmps, err := filepath.Glob(filepath.Join(coldDir, ".rotate-"+segName+"-*"))
	if err != nil {
		return fmt.Errorf("retention: scan temporaries: %w", err)
	}
	for _, tmp := range tmps {
		// Removal can fail under a WORM mount (object-locked orphan): inert by
		// construction, so a failed cleanup is not an error.
		_ = fs.Remove(tmp)
	}

	finalPath := filepath.Join(coldDir, segName)
	_, coldErr := os.Stat(finalPath)
	_, hotErr := os.Stat(hotPath)
	coldExists := coldErr == nil
	hotExists := hotErr == nil

	switch {
	case coldExists && hotExists:
		coldBytes, err := fs.ReadFile(finalPath)
		if err != nil {
			return fmt.Errorf("retention: read cold copy for resume: %w", err)
		}
		hotBytes, err := fs.ReadFile(hotPath)
		if err != nil {
			return fmt.Errorf("retention: read hot copy for resume: %w", err)
		}
		if !bytes.Equal(coldBytes, hotBytes) {
			return fmt.Errorf("%w: segment %s", ErrDivergentCopies, segName)
		}
		if err := fs.Remove(hotPath); err != nil {
			return fmt.Errorf("retention: finish removal of rotated %s: %w", segName, err)
		}
		return fs.SyncDir(filepath.Dir(hotPath))
	default:
		return nil
	}
}

// verifyFrames re-reads a segment through the WAL frame reader, which hard-
// errors on any interior CRC mismatch.
func verifyFrames(path string) error {
	_, err := wal.ReadAll(path)
	return err
}
