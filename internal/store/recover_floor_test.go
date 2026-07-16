// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package store

import (
	"path/filepath"
	"testing"

	"github.com/Wide-Moat/ocu-audit/internal/wal"
)

// TestRecoverRestoresIngestTimeFloor extends NFR-SEC-48's monotonic floor
// ACROSS a restart. The floor lives only in memory; a Recover that rebuilt
// chains but not the floor would let a wall-clock rollback across a restart
// stamp a new record BELOW a committed IngestTime — the exact backdating the
// floor exists to prevent, reopened through the boot path.
func TestRecoverRestoresIngestTimeFloor(t *testing.T) {
	p := filepath.Join(t.TempDir(), "floor.wal")

	// Generation 1: the clock reads 5000; one committed record carries
	// IngestTime 5000.
	w, err := wal.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	gen1 := New(w, &fakeClock{times: []int64{5000}})
	if _, err := gen1.Admit("control-plane", env(1)); err != nil {
		t.Fatalf("gen1 admit: %v", err)
	}
	if err := gen1.Close(); err != nil {
		t.Fatal(err)
	}

	// Restart with a ROLLED-BACK clock reading 400.
	gen2, err := Recover(p, &fakeClock{times: []int64{400}})
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	t.Cleanup(func() { _ = gen2.Close() })

	rec, err := gen2.Admit("control-plane", env(2))
	if err != nil {
		t.Fatalf("gen2 admit: %v", err)
	}
	if rec.IngestTime < 5000 {
		t.Fatalf("post-restart IngestTime = %d, below the committed floor 5000; "+
			"a clock rollback across a restart backdated the trusted stamp (NFR-SEC-48)",
			rec.IngestTime)
	}
	// The whole WAL stays verifiable across the restart and the floored admit.
	if _, err := VerifyChainsFromRaw(gen2.Records()); err != nil {
		t.Fatalf("chains do not verify after a floored post-restart admit: %v", err)
	}
}
