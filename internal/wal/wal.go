// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package wal is the embedded append-only write-ahead log that is the solo-
// shelf durable bus (ADR-0009: the minimal-shelf durable-commit is OCU code,
// no bus product to pick). It provides the local durable commit that every
// admitted event reaches before its publish is acknowledged (INV-4,
// NFR-REL-03 RPO=0): Append writes a length-framed record, fsyncs, and only
// then returns. A caller that does not observe a nil error from Append must
// treat the event as uncommitted and refuse the source's ack.
//
// The frame is: uint32-BE payload-length || uint32-BE CRC32(payload) ||
// payload. The CRC lets the reader detect a bit-flip in a middle record
// independently of the hash chain, so a corrupt WAL is distinguishable from a
// forged-but-well-framed one.
package wal

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// maxRecord bounds a single WAL frame (NFR-SEC-51 defensive cap): a corrupt
// length prefix cannot make the reader allocate an unbounded buffer.
const maxRecord = 8 << 20 // 8 MiB

// Syncer is the durability seam. The production implementation calls
// (*os.File).Sync; tests inject a fault to prove Append refuses (returns an
// error, so no 200) when the fsync cannot be guaranteed.
type Syncer interface {
	Sync() error
}

// WAL is an append-only log file. It is safe for concurrent Append/Read from
// multiple goroutines.
type WAL struct {
	mu     sync.Mutex
	f      *os.File
	w      *bufio.Writer
	sync   Syncer
	closed bool
	// path is the active file's own path, kept so SealTo can rename it and
	// reopen a fresh active file at the same place.
	path string
}

// Open opens (creating if absent) the WAL at path in append mode. The file's
// own Sync is the default durability seam.
func Open(path string) (*WAL, error) {
	// #nosec G304 -- path is the operator's -wal flag, not caller input. The
	// daemon must open the WAL the deployment names; there is no allow-list to
	// check it against, and refusing a variable path would mean hardcoding one.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open wal %q: %w", path, err)
	}
	return &WAL{f: f, w: bufio.NewWriter(f), sync: f, path: path}, nil
}

// SealTo closes the current active file and atomically renames it to
// sealedPath (same directory), then reopens a fresh active file at the
// original path (ADR-0045). It holds the append mutex for the whole seal, so
// a concurrent Append lands wholly in the sealed segment or wholly in the
// fresh active file — never torn across the boundary, never refused.
//
// Order matters for durability: flush + fsync the outgoing file BEFORE the
// rename (its bytes are durable under the new name), fsync the directory
// AFTER (the rename itself is durable), and only then reopen. A crash between
// rename and reopen leaves a sealed segment plus no active file; the next
// Open creates a fresh active, which is exactly the post-seal state.
func (w *WAL) SealTo(sealedPath string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ErrClosed
	}
	if err := w.w.Flush(); err != nil {
		return fmt.Errorf("wal: seal flush: %w", err)
	}
	if err := w.sync.Sync(); err != nil {
		return fmt.Errorf("wal: seal fsync: %w", err)
	}
	if err := w.f.Close(); err != nil {
		return fmt.Errorf("wal: seal close: %w", err)
	}
	if err := os.Rename(w.path, sealedPath); err != nil {
		// The outgoing file is closed; reopen it as the active file again so
		// the WAL stays usable after a failed rename.
		if f, rerr := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); rerr == nil { // #nosec G304 -- operator's -wal path
			w.f, w.w, w.sync = f, bufio.NewWriter(f), f
		} else {
			w.closed = true
		}
		return fmt.Errorf("wal: seal rename: %w", err)
	}
	if err := syncDir(filepath.Dir(sealedPath)); err != nil {
		return err
	}
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- operator's -wal path
	if err != nil {
		w.closed = true
		return fmt.Errorf("wal: reopen active after seal: %w", err)
	}
	w.f, w.w, w.sync = f, bufio.NewWriter(f), f
	return nil
}

// SetSyncer replaces the durability seam. Intended for fault injection in
// tests; production leaves the *os.File default.
func (w *WAL) SetSyncer(s Syncer) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.sync = s
}

// ErrClosed is returned by Append after Close.
var ErrClosed = errors.New("wal: closed")

// Append frames payload, writes it, flushes to the OS, and fsyncs. It returns
// nil ONLY after the fsync succeeds: this is the durable-commit point, so a nil
// return is the sole license to ack the source (INV-4). If the fsync (or any
// prior write) fails, Append returns a non-nil error and the caller MUST NOT
// ack. On a sync fault the frame may be partially written; the reader's CRC and
// length checks discard a trailing torn frame, so a fault leaves no admitted-
// but-uncommitted record visible to the verifier.
func (w *WAL) Append(payload []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ErrClosed
	}
	if len(payload) > maxRecord {
		return fmt.Errorf("wal: record %d bytes exceeds cap %d", len(payload), maxRecord)
	}
	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[0:4], uint32(len(payload)))
	binary.BigEndian.PutUint32(hdr[4:8], crc32.ChecksumIEEE(payload))
	if _, err := w.w.Write(hdr[:]); err != nil {
		return fmt.Errorf("wal: write header: %w", err)
	}
	if _, err := w.w.Write(payload); err != nil {
		return fmt.Errorf("wal: write payload: %w", err)
	}
	if err := w.w.Flush(); err != nil {
		return fmt.Errorf("wal: flush: %w", err)
	}
	if err := w.sync.Sync(); err != nil {
		// Durability not guaranteed: refuse. The caller returns non-200.
		return fmt.Errorf("wal: fsync: %w", err)
	}
	return nil
}

// Close flushes and closes the underlying file.
func (w *WAL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	ferr := w.w.Flush()
	cerr := w.f.Close()
	if ferr != nil {
		return ferr
	}
	return cerr
}

// ReadAll reads every intact frame from the WAL at path in append order,
// returning each record's payload bytes. A trailing torn frame (a crash or
// injected fault mid-append) is dropped, not surfaced as a record; a CRC
// mismatch on a fully-framed record is a hard error (a middle-record
// corruption / tamper) so the verifier reds rather than silently skipping it.
func ReadAll(path string) ([][]byte, error) {
	// #nosec G304 -- same operator-supplied path as Open above; the verifier
	// reads the WAL the operator names.
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open wal %q: %w", path, err)
	}
	defer f.Close()
	r := bufio.NewReader(f)
	var out [][]byte
	for {
		var hdr [8]byte
		n, err := io.ReadFull(r, hdr[:])
		if errors.Is(err, io.EOF) && n == 0 {
			return out, nil // clean end
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return out, nil // torn header: trailing partial frame, drop
		}
		if err != nil {
			return nil, fmt.Errorf("wal: read header: %w", err)
		}
		length := binary.BigEndian.Uint32(hdr[0:4])
		want := binary.BigEndian.Uint32(hdr[4:8])
		if length > maxRecord {
			return nil, fmt.Errorf("wal: framed length %d exceeds cap %d (corrupt)", length, maxRecord)
		}
		buf := make([]byte, length)
		if _, err := io.ReadFull(r, buf); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return out, nil // torn payload: trailing partial frame, drop
			}
			return nil, fmt.Errorf("wal: read payload: %w", err)
		}
		if got := crc32.ChecksumIEEE(buf); got != want {
			return nil, fmt.Errorf("wal: crc mismatch at record %d (got %08x want %08x): corrupt log",
				len(out), got, want)
		}
		out = append(out, buf)
	}
}
