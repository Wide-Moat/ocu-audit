// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package retention enforces the NFR-COMP-01 two-tier audit retention on the
// segmented store (ADR-0045): hot <= 90 d, then cold to the 7-year floor. The
// policy decisions are pure functions over an injected clock; the rotation
// executor moves sealed segments hot -> cold as copy-verify-rename; the
// signed checkpoint anchors hot-only boot. Nothing in this package deletes a
// committed record — disposal at floor expiry has no code path.
package retention

import (
	"fmt"
	"time"
)

// FloorYearsMinimum is the NFR-COMP-01 retention floor. A configured floor
// below it refuses to construct; a longer floor never violates a floor.
const FloorYearsMinimum = 7

// HotMaxCeiling is the NFR-COMP-01 hot-tier ceiling: every record leaves the
// hot tier within 90 days.
const HotMaxCeiling = 90 * 24 * time.Hour

// Policy is the validated retention configuration.
type Policy struct {
	// FloorYears is the retention floor in years, >= FloorYearsMinimum.
	FloorYears int
	// HotMax is how long a record may stay in the hot tier, <= HotMaxCeiling.
	HotMax time.Duration
	// SealInterval is the cadence sealed segments are cut at. Rotation
	// eligibility subtracts it from HotMax so the OLDEST record of a segment
	// leaves hot before the ceiling even in the worst alignment.
	SealInterval time.Duration
}

// NewPolicy validates a policy. Violations REFUSE (fail-closed) rather than
// clamp: a clamped compliance parameter would silently run a different policy
// than the operator declared.
func NewPolicy(floorYears int, hotMax, sealInterval time.Duration) (Policy, error) {
	if floorYears < FloorYearsMinimum {
		return Policy{}, fmt.Errorf("retention: floor %d y is below the NFR-COMP-01 minimum %d y", floorYears, FloorYearsMinimum)
	}
	if hotMax <= 0 || hotMax > HotMaxCeiling {
		return Policy{}, fmt.Errorf("retention: hot ceiling %v outside (0, %v]", hotMax, HotMaxCeiling)
	}
	if sealInterval <= 0 || sealInterval >= hotMax {
		return Policy{}, fmt.Errorf("retention: seal interval %v outside (0, hot ceiling %v)", sealInterval, hotMax)
	}
	return Policy{FloorYears: floorYears, HotMax: hotMax, SealInterval: sealInterval}, nil
}

// SegmentAges summarizes one sealed hot segment for the rotation decision.
type SegmentAges struct {
	// Name is the segment file name (audit-NNNNNN.wal).
	Name string
	// OldestIngestMillis is the hash-bound IngestTime of the segment's oldest
	// record — the trusted stamp (NFR-SEC-48), not a file mtime a rollback
	// could rewrite.
	OldestIngestMillis int64
}

// RotationDue reports whether the segment's oldest record has aged to the
// rotation threshold: HotMax - SealInterval. Rotating at that margin
// guarantees the record is out of hot before the ceiling even when it landed
// at the very start of its seal window.
func (p Policy) RotationDue(nowMillis int64, seg SegmentAges) bool {
	age := time.Duration(nowMillis-seg.OldestIngestMillis) * time.Millisecond
	return age >= p.HotMax-p.SealInterval
}

// CeilingBreached reports whether the segment's oldest record has exceeded
// the hot ceiling itself — the condition that self-emits a chain-linked
// breach record (ADR-0045: enforcement failure is loud evidence, never a
// silent log line).
func (p Policy) CeilingBreached(nowMillis int64, seg SegmentAges) bool {
	age := time.Duration(nowMillis-seg.OldestIngestMillis) * time.Millisecond
	return age > p.HotMax
}
