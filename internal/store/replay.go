// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package store

import (
	"encoding/json"
	"fmt"

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
