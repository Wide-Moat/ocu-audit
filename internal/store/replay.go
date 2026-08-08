// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Wide-Moat/ocu-audit/internal/ocsf"
	"github.com/Wide-Moat/ocu-audit/internal/wal"
)

// ReadRawRecords reads the WAL at path and decodes each frame into an
// ocsf.Record in commit order, WITHOUT any chain or sequence validation. It is
// the raw-bytes reader the independent verifier uses so its checks recompute
// from the stored bytes rather than trusting an in-memory oracle.
func ReadRawRecords(path string) ([]*ocsf.Record, error) {
	frames, err := wal.ReadAll(path)
	if err != nil {
		return nil, err
	}
	out := make([]*ocsf.Record, 0, len(frames))
	for i, fr := range frames {
		var rec ocsf.Record
		if err := json.Unmarshal(fr, &rec); err != nil {
			return nil, fmt.Errorf("store: decode wal frame %d: %w", i, err)
		}
		out = append(out, &rec)
	}
	return out, nil
}

// ReadHotRecords reads the hot tier as one commit-ordered union: sealed
// segments (in index order) from the active file's directory, then the active
// file itself (ADR-0045 stage 1). With no sealed segments it degrades to the
// single-file read, so pre-segmentation WALs keep working. An absent active
// file with sealed segments present is a crash-between-rename-and-reopen; the
// union is just the segments.
func ReadHotRecords(activePath string) ([]*ocsf.Record, error) {
	return readHotRecordsExcluding(activePath, nil)
}

// readHotRecordsExcluding reads the hot union, skipping segments whose base
// name appears in exclude — the rotated-but-pending-removal state (ADR-0045):
// their records are cold-anchored, and counting them again would double-count
// the prefix the boot anchor already covers.
func readHotRecordsExcluding(activePath string, exclude map[string]struct{}) ([]*ocsf.Record, error) {
	segs, err := wal.ListSegments(filepath.Dir(activePath))
	if err != nil {
		return nil, err
	}
	var out []*ocsf.Record
	for _, seg := range segs {
		if _, skip := exclude[filepath.Base(seg)]; skip {
			continue
		}
		recs, err := ReadRawRecords(seg)
		if err != nil {
			return nil, fmt.Errorf("store: segment %s: %w", filepath.Base(seg), err)
		}
		out = append(out, recs...)
	}
	recs, err := ReadRawRecords(activePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && len(segs) > 0 {
			return out, nil // crash between seal-rename and reopen
		}
		return nil, err
	}
	return append(out, recs...), nil
}

// ReadUnion reads the WHOLE horizon for the offline verifier (ADR-0045):
// cold segments in index order, then the hot union, excluding hot leftovers
// of segments already rotated (a pending-removal duplicate is byte-compared —
// identical is fine, divergent is a tamper signal and errors). The daemon
// never calls this; boot is hot-only.
func ReadUnion(coldDir, activePath string) ([]*ocsf.Record, error) {
	coldSegs, err := wal.ListSegments(coldDir)
	if err != nil {
		return nil, err
	}
	var out []*ocsf.Record
	coldNames := make(map[string]struct{}, len(coldSegs))
	for _, seg := range coldSegs {
		name := filepath.Base(seg)
		coldNames[name] = struct{}{}
		recs, err := ReadRawRecords(seg)
		if err != nil {
			return nil, fmt.Errorf("store: cold segment %s: %w", name, err)
		}
		out = append(out, recs...)
		// A hot leftover of a rotated segment must byte-match its cold copy.
		hotPath := filepath.Join(filepath.Dir(activePath), name)
		if hotBytes, herr := os.ReadFile(hotPath); herr == nil { // #nosec G304 -- verifier-owned tier paths
			coldBytes, cerr := os.ReadFile(seg) // #nosec G304
			if cerr != nil {
				return nil, cerr
			}
			if !bytes.Equal(hotBytes, coldBytes) {
				return nil, fmt.Errorf("store: segment %s diverges between hot and cold copies", name)
			}
		}
	}
	hot, err := readHotRecordsExcluding(activePath, coldNames)
	if err != nil {
		return nil, err
	}
	return append(out, hot...), nil
}
