// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package retention

import (
	"strings"
	"testing"
	"time"
)

// Every boundary here is a LITERAL duration, never derived from the package's
// own constants: a test that derives its threshold from the constant under
// test shifts with a mutated constant and cannot red-probe it.

func TestNewPolicyRefusesFloorBelowSeven(t *testing.T) {
	if _, err := NewPolicy(6, 2160*time.Hour, 24*time.Hour); err == nil {
		t.Fatal("floor 6 y accepted; NFR-COMP-01 minimum is 7")
	}
	if _, err := NewPolicy(7, 2160*time.Hour, 24*time.Hour); err != nil {
		t.Fatalf("floor 7 y refused: %v", err)
	}
	// Longer floors never violate a floor.
	if _, err := NewPolicy(12, 2160*time.Hour, 24*time.Hour); err != nil {
		t.Fatalf("floor 12 y refused: %v", err)
	}
}

func TestNewPolicyRefusesHotCeilingAboveNinetyDays(t *testing.T) {
	if _, err := NewPolicy(7, 91*24*time.Hour, 24*time.Hour); err == nil {
		t.Fatal("hot ceiling 91 d accepted; NFR-COMP-01 ceiling is 90 d")
	}
	if _, err := NewPolicy(7, 90*24*time.Hour, 24*time.Hour); err != nil {
		t.Fatalf("hot ceiling exactly 90 d refused: %v", err)
	}
}

func TestNewPolicyRefusesDegenerateSealInterval(t *testing.T) {
	if _, err := NewPolicy(7, 2160*time.Hour, 0); err == nil {
		t.Fatal("zero seal interval accepted")
	}
	if _, err := NewPolicy(7, 2160*time.Hour, 2160*time.Hour); err == nil {
		t.Fatal("seal interval equal to the hot ceiling accepted; the rotation margin would be zero or negative")
	}
}

// TestNewPolicyRefusalsAreDistinct binds each guard to its own diagnostic —
// a guard whose refusal a neighboring check repeats is otherwise unverifiable.
func TestNewPolicyRefusalsAreDistinct(t *testing.T) {
	_, floorErr := NewPolicy(6, 2160*time.Hour, 24*time.Hour)
	_, hotErr := NewPolicy(7, 91*24*time.Hour, 24*time.Hour)
	_, sealErr := NewPolicy(7, 2160*time.Hour, 2160*time.Hour)
	if floorErr == nil || !strings.Contains(floorErr.Error(), "floor") {
		t.Fatalf("floor refusal diagnostic = %v, want a floor-specific message", floorErr)
	}
	if hotErr == nil || !strings.Contains(hotErr.Error(), "hot ceiling") {
		t.Fatalf("hot-ceiling refusal diagnostic = %v, want a hot-ceiling-specific message", hotErr)
	}
	if sealErr == nil || !strings.Contains(sealErr.Error(), "seal interval") {
		t.Fatalf("seal-interval refusal diagnostic = %v, want a seal-interval-specific message", sealErr)
	}
}

// TestRotationDueBoundary pins the eligibility comparison on both sides with
// literal times. Policy: HotMax 2160 h (90 d), SealInterval 24 h, so the
// rotation threshold is 2136 h. A segment aged 2135h59m59s stays hot; at
// exactly 2136 h it rotates.
func TestRotationDueBoundary(t *testing.T) {
	p, err := NewPolicy(7, 2160*time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	const epsilon = time.Second
	seg := SegmentAges{Name: "audit-000001.wal", OldestIngestMillis: 0}

	underMillis := (2136*time.Hour - epsilon).Milliseconds()
	if p.RotationDue(underMillis, seg) {
		t.Fatal("segment aged 2136h - 1s rotated; the margin fired early")
	}
	atMillis := (2136 * time.Hour).Milliseconds()
	if !p.RotationDue(atMillis, seg) {
		t.Fatal("segment aged exactly 2136h (HotMax 2160h - SealInterval 24h) stayed hot; " +
			"its oldest record can now breach the 90 d ceiling before the next seal")
	}
}

// TestCeilingBreachedBoundary pins the breach detector with literals: 2160 h
// exactly is not yet a breach, one second past is.
func TestCeilingBreachedBoundary(t *testing.T) {
	p, err := NewPolicy(7, 2160*time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	seg := SegmentAges{Name: "audit-000001.wal", OldestIngestMillis: 0}
	if p.CeilingBreached((2160 * time.Hour).Milliseconds(), seg) {
		t.Fatal("age exactly 2160h reported as a breach; the ceiling is inclusive")
	}
	if !p.CeilingBreached((2160*time.Hour + time.Second).Milliseconds(), seg) {
		t.Fatal("age 2160h + 1s not reported as a breach; the ceiling never fires")
	}
}
