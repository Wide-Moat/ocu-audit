// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package store

import (
	"testing"
)

// NFR-SEC-48: the committed record carries a pipeline-stamped TRUSTED
// wall-clock. The store stamps IngestTime at commit from an injected clock, and
// the stamp is monotonic-floored — a wall-clock rollback must not backdate a
// committed record below the floor already reached, or the "trusted" stamp is
// exactly as forgeable as the source clock it exists to distrust.

// fakeClock returns scripted times, advancing through them on each read.
type fakeClock struct {
	times []int64
	i     int
}

func (c *fakeClock) NowMillis() int64 {
	t := c.times[c.i]
	if c.i < len(c.times)-1 {
		c.i++
	}
	return t
}

func newStoreWithClock(t *testing.T, clk Clock) *Store {
	t.Helper()
	st, _ := newStore(t)
	st.clock = clk
	return st
}

// TestIngestTimeStampedAtCommit is the base property: a committed record carries
// the clock's time, not the source's.
func TestIngestTimeStampedAtCommit(t *testing.T) {
	st := newStoreWithClock(t, &fakeClock{times: []int64{5000}})

	rec, err := st.Admit("control-plane", env(1))
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if rec.IngestTime != 5000 {
		t.Errorf("IngestTime = %d, want the clock's 5000 — the stamp is not the "+
			"pipeline's trusted time", rec.IngestTime)
	}
}

// TestIngestTimeIsMonotonicFloored is the security property. The clock rolls
// backward mid-stream; a record committed during the rollback window must carry
// the floor (the highest time already reached), never the setback time. A
// trusted stamp that a rollback could lower would be no more trustworthy than
// the source clock.
func TestIngestTimeIsMonotonicFloored(t *testing.T) {
	// 1000, then a rollback to 400, then 1200.
	st := newStoreWithClock(t, &fakeClock{times: []int64{1000, 400, 1200}})

	r1, _ := st.Admit("control-plane", env(1))
	r2, _ := st.Admit("control-plane", env(2)) // clock reads 400 (rolled back)
	r3, _ := st.Admit("control-plane", env(3)) // clock reads 1200

	if r1.IngestTime != 1000 {
		t.Errorf("r1 IngestTime = %d, want 1000", r1.IngestTime)
	}
	if r2.IngestTime < r1.IngestTime {
		t.Errorf("r2 IngestTime = %d regressed below r1's %d during a clock rollback; "+
			"the floor did not hold", r2.IngestTime, r1.IngestTime)
	}
	if r3.IngestTime < r2.IngestTime {
		t.Errorf("r3 IngestTime = %d regressed below r2's %d", r3.IngestTime, r2.IngestTime)
	}
	// The stream stays verifiable across the rollback.
	if _, err := VerifyChainsFromRaw(st.Records()); err != nil {
		t.Fatalf("the chain does not verify across a clock rollback: %v", err)
	}
}

// TestIngestTimeSurvivesTheWAL keeps the stamp durable: a record read back from
// the WAL carries the IngestTime it was committed with, or the trusted stamp is
// not actually persisted.
func TestIngestTimeSurvivesTheWAL(t *testing.T) {
	st := newStoreWithClock(t, &fakeClock{times: []int64{7777}})
	if _, err := st.Admit("control-plane", env(1)); err != nil {
		t.Fatalf("admit: %v", err)
	}
	got := st.Records()
	if len(got) != 1 || got[0].IngestTime != 7777 {
		t.Fatalf("the committed record carries IngestTime %d, want 7777", got[0].IngestTime)
	}
}
