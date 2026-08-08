// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package wal

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
)

// Sealed-segment naming (ADR-0045): the active file is renamed to
// audit-NNNNNN.wal on seal, in commit order. The name order is a hint the
// verifier cross-checks — per-source chain linkage is the ordering authority,
// and any misordering fails chain verification.

// segmentPattern matches any audit-<digits>.wal name. SegmentName always
// zero-pads to six digits; the permissive digit run exists so a hand-renamed
// or foreign variant claiming the same index is DETECTED as a collision
// rather than silently shadowing a real segment.
var segmentPattern = regexp.MustCompile(`^audit-(\d+)\.wal$`)

// SegmentName returns the sealed-segment file name for a 1-based segment
// index.
func SegmentName(index uint64) string {
	return fmt.Sprintf("audit-%06d.wal", index)
}

// ListSegments returns the sealed segments in dir as full paths ordered by
// segment index. Non-segment names (the active audit.wal, heads, manifests)
// are ignored. Two names parsing to the same index would make the commit
// order ambiguous, so that is an error, never a silent pick.
func ListSegments(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("wal: list segments in %q: %w", dir, err)
	}
	type seg struct {
		index uint64
		path  string
	}
	var segs []seg
	seen := make(map[uint64]string)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		m := segmentPattern.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		idx, err := strconv.ParseUint(m[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("wal: segment name %q: %w", e.Name(), err)
		}
		if prev, dup := seen[idx]; dup {
			return nil, fmt.Errorf("wal: %q and %q both parse to segment index %d; commit order is ambiguous", e.Name(), prev, idx)
		}
		seen[idx] = e.Name()
		segs = append(segs, seg{index: idx, path: filepath.Join(dir, e.Name())})
	}
	sort.Slice(segs, func(i, j int) bool { return segs[i].index < segs[j].index })
	out := make([]string, len(segs))
	for i, s := range segs {
		out[i] = s.path
	}
	return out, nil
}

// syncDir fsyncs a directory so a rename inside it is durable.
func syncDir(dir string) error {
	d, err := os.Open(dir) // #nosec G304 -- dir derives from the operator's -wal flag
	if err != nil {
		return fmt.Errorf("wal: open dir %q: %w", dir, err)
	}
	serr := d.Sync()
	cerr := d.Close()
	if serr != nil {
		return fmt.Errorf("wal: fsync dir %q: %w", dir, serr)
	}
	return cerr
}
