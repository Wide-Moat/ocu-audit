// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package retention

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Wide-Moat/ocu-audit/internal/signer"
	"github.com/Wide-Moat/ocu-audit/internal/store"
	"github.com/Wide-Moat/ocu-audit/internal/wal"
)

// Self-emitted evidence actions (ADR-0045, NFR-SEC-45). Payload schemas stay
// minimal: OCSF v1.x ships no class for them (component-07 Open Question).
const (
	ActionRotationFailure = "retention.rotation_failure"
	ActionCeilingBreach   = "retention.ceiling_breach"
	ActionPolicyChange    = "retention.policy_change"
	ActionSealFailure     = "retention.seal_failure"
)

// SealSnapshot mirrors store.SealSnapshot: the seal-point anchors. Aliased so
// the Manager's seams stay function-typed and a test needs no store.
type SealSnapshot = store.SealSnapshot

// ChainTipFromStore converts the store's tip type.
func chainTipsFromStore(tips map[string]store.ChainTip) map[string]ChainTip {
	out := make(map[string]ChainTip, len(tips))
	for src, t := range tips {
		out[src] = ChainTip{Hash: append([]byte(nil), t.Hash...), Seq: t.Seq}
	}
	return out
}

// ManagerConfig wires the Manager's seams. Everything is a function or a
// value, so tests drive the Manager without a daemon.
type ManagerConfig struct {
	Policy         Policy
	HotDir         string
	ColdDir        string
	CheckpointPath string
	Signer         *signer.Signer
	// CurrentCount reports the GLOBAL committed-record count (rotated +
	// hot); a seal is due only when it exceeds the checkpointed boundary.
	CurrentCount func() uint64
	// Seal seals the active file to the given path and returns the
	// seal-point anchors (store.SealActive in production).
	Seal func(sealedPath string) (SealSnapshot, error)
	// Emit self-emits one evidence record on the pipeline's own channel
	// (ADR-0045 / NFR-SEC-45). nil drops the evidence (tests only).
	Emit func(action, resource string, payload map[string]any)
}

// Manager runs the retention loop as one deterministic Tick at a time. It is
// driven by a single goroutine (the daemon's ticker); Tick is not safe for
// concurrent use.
type Manager struct {
	cfg ManagerConfig
	cp  Checkpoint
	// Episode trackers: one evidence record per failure episode, per segment
	// (a healed rotation resets the episode).
	failureEmitted map[string]bool
	breachEmitted  map[string]bool
}

// NewManager loads (or initializes) the checkpoint and returns the manager.
// A checkpoint on disk must signature-verify and pass the shrink gate, or
// construction refuses (the daemon treats that as refuse-boot).
func NewManager(cfg ManagerConfig) (*Manager, error) {
	m := &Manager{
		cfg:            cfg,
		failureEmitted: make(map[string]bool),
		breachEmitted:  make(map[string]bool),
	}
	cp, err := LoadCheckpoint(cfg.CheckpointPath, cfg.Signer.PublicKey(), cfg.Policy)
	switch {
	case err == nil:
		m.cp = cp
	case errors.Is(err, os.ErrNotExist):
		// First boot: an empty checkpoint pinned at the configured policy.
		m.cp = Checkpoint{Policy: cfg.Policy}
	default:
		return nil, err
	}
	return m, nil
}

// PublicKey exposes the signing key's public half (checkpoint verification).
func (m *Manager) PublicKey() []byte { return m.cfg.Signer.PublicKey() }

// ConfiguredPolicy returns the policy the manager runs.
func (m *Manager) ConfiguredPolicy() Policy { return m.cfg.Policy }

// Checkpoint returns the current in-memory checkpoint (the boot anchor
// source for the daemon).
func (m *Manager) Checkpoint() Checkpoint { return m.cp }

// SetPolicyForTestOfBootSync swaps the configured policy; only the boot-sync
// test uses it to model a restart with new flags.
func (m *Manager) SetPolicyForTestOfBootSync(p Policy) { m.cfg.Policy = p }

// BootPolicySync compares the configured policy against the checkpointed one
// at boot: any change (necessarily a non-shrink — Load refuses shrinks)
// self-emits the NFR-SEC-45 policy-change record and repins the checkpoint.
func (m *Manager) BootPolicySync() error {
	if m.cp.Policy == m.cfg.Policy {
		return nil
	}
	old := m.cp.Policy
	m.cp.Policy = m.cfg.Policy
	if err := m.writeCheckpoint(); err != nil {
		m.cp.Policy = old
		return err
	}
	m.emit(ActionPolicyChange, "retention-policy", map[string]any{
		"old_floor_years": old.FloorYears,
		"new_floor_years": m.cfg.Policy.FloorYears,
		"old_hot_max_ms":  old.HotMax.Milliseconds(),
		"new_hot_max_ms":  m.cfg.Policy.HotMax.Milliseconds(),
	})
	return nil
}

// Tick runs one retention round at the given trusted time: seal if due,
// rotate due segments in index order, and emit ceiling-breach evidence for
// segments stuck hot. Failures never propagate to admission — they self-emit
// once per episode and retry on a later tick.
func (m *Manager) Tick(nowMillis int64) {
	m.maybeSeal(nowMillis)
	m.rotateDue(nowMillis)
	m.emitBreaches(nowMillis)
}

// maybeSeal seals the active file when the seal interval has elapsed since
// the last seal AND new records exist beyond the sealed boundary.
func (m *Manager) maybeSeal(nowMillis int64) {
	var lastSeal int64
	var boundary uint64
	for _, s := range m.cp.Segments {
		if s.SealedAtMillis > lastSeal {
			lastSeal = s.SealedAtMillis
		}
		if s.LastGlobalIndex+1 > boundary {
			boundary = s.LastGlobalIndex + 1
		}
	}
	if nowMillis-lastSeal < m.cfg.Policy.SealInterval.Milliseconds() {
		return
	}
	current := m.cfg.CurrentCount()
	if current <= boundary {
		return // nothing new to seal
	}
	nextIndex := uint64(len(m.cp.Segments)) + 1
	segName := wal.SegmentName(nextIndex)
	sealedPath := filepath.Join(m.cfg.HotDir, segName)
	snap, err := m.cfg.Seal(sealedPath)
	if err != nil {
		if !m.failureEmitted[segName] {
			m.failureEmitted[segName] = true
			m.emit(ActionSealFailure, segName, map[string]any{"error": err.Error()})
		}
		return
	}
	entry, err := m.inventorySealed(sealedPath, snap, boundary, nowMillis)
	if err != nil {
		if !m.failureEmitted[segName] {
			m.failureEmitted[segName] = true
			m.emit(ActionSealFailure, segName, map[string]any{"error": err.Error()})
		}
		return
	}
	m.cp.Segments = append(m.cp.Segments, entry)
	if err := m.writeCheckpoint(); err != nil {
		// The segment is sealed on disk but not yet inventoried; the next
		// boot's plain hot union still reads it (it is not rotated), so
		// nothing is lost. Emit and retry the checkpoint on the next tick.
		m.emit(ActionSealFailure, segName, map[string]any{"error": err.Error()})
	}
	m.failureEmitted[segName] = false
}

// inventorySealed builds the sealed segment's inventory entry: digest and
// IngestTime bounds from the segment bytes, anchors from the seal snapshot.
func (m *Manager) inventorySealed(sealedPath string, snap SealSnapshot, firstGlobal uint64, nowMillis int64) (SegmentEntry, error) {
	raw, err := os.ReadFile(sealedPath) // #nosec G304 -- manager-owned segment path
	if err != nil {
		return SegmentEntry{}, fmt.Errorf("retention: read sealed segment: %w", err)
	}
	recs, err := store.ReadRawRecords(sealedPath)
	if err != nil {
		return SegmentEntry{}, fmt.Errorf("retention: decode sealed segment: %w", err)
	}
	if len(recs) == 0 {
		return SegmentEntry{}, fmt.Errorf("retention: sealed segment %s is empty", filepath.Base(sealedPath))
	}
	first, last := recs[0].IngestTime, recs[0].IngestTime
	for _, r := range recs {
		if r.IngestTime < first {
			first = r.IngestTime
		}
		if r.IngestTime > last {
			last = r.IngestTime
		}
	}
	sum := sha256.Sum256(raw)
	return SegmentEntry{
		Name:              filepath.Base(sealedPath),
		SHA256:            sum[:],
		RecordCount:       uint64(len(recs)),
		FirstIngestMillis: first,
		LastIngestMillis:  last,
		FirstGlobalIndex:  firstGlobal,
		LastGlobalIndex:   firstGlobal + uint64(len(recs)) - 1,
		SealedAtMillis:    nowMillis,
		SealTips:          chainTipsFromStore(snap.Tips),
		SealTreeSize:      snap.TreeSize,
		SealFrontier:      snap.Frontier,
	}, nil
}

// rotateDue rotates due segments strictly in index order, stopping at the
// first failure (a later segment must never rotate past an earlier one, or
// the anchor promotion order breaks).
func (m *Manager) rotateDue(nowMillis int64) {
	for i := range m.cp.Segments {
		seg := &m.cp.Segments[i]
		if seg.RotatedAtMillis != 0 {
			continue
		}
		if !m.cfg.Policy.RotationDue(nowMillis, SegmentAges{Name: seg.Name, OldestIngestMillis: seg.FirstIngestMillis}) {
			return // in-order: later segments are younger
		}
		hotPath := filepath.Join(m.cfg.HotDir, seg.Name)
		if err := RotateCopy(osFS{}, hotPath, m.cfg.ColdDir); err != nil {
			if !m.failureEmitted[seg.Name] {
				m.failureEmitted[seg.Name] = true
				m.emit(ActionRotationFailure, seg.Name, map[string]any{"error": err.Error()})
			}
			return
		}
		// Checkpoint BEFORE hot removal (ADR-0045 ordering): a crash between
		// them boots anchored with the segment excluded, never unanchored
		// with it missing.
		seg.RotatedAtMillis = nowMillis
		m.cp.ChainTips = seg.SealTips
		m.cp.TreeSize = seg.SealTreeSize
		m.cp.Frontier = seg.SealFrontier
		if err := m.writeCheckpoint(); err != nil {
			// Roll the in-memory promotion back; cold copy stays (identical
			// both-copies resume on a later tick).
			seg.RotatedAtMillis = 0
			if !m.failureEmitted[seg.Name] {
				m.failureEmitted[seg.Name] = true
				m.emit(ActionRotationFailure, seg.Name, map[string]any{"error": err.Error()})
			}
			return
		}
		if err := FinishRotation(osFS{}, hotPath); err != nil {
			// The checkpoint says rotated; boot excludes the leftover and a
			// later tick's ResumeSegment finishes the removal.
			m.emit(ActionRotationFailure, seg.Name, map[string]any{"error": err.Error(), "phase": "finish"})
		}
		m.failureEmitted[seg.Name] = false
		m.breachEmitted[seg.Name] = false
	}
}

// emitBreaches emits ceiling-breach evidence once per episode for unrotated
// segments past the hot ceiling.
func (m *Manager) emitBreaches(nowMillis int64) {
	for _, seg := range m.cp.Segments {
		if seg.RotatedAtMillis != 0 {
			continue
		}
		if m.cfg.Policy.CeilingBreached(nowMillis, SegmentAges{Name: seg.Name, OldestIngestMillis: seg.FirstIngestMillis}) {
			if !m.breachEmitted[seg.Name] {
				m.breachEmitted[seg.Name] = true
				m.emit(ActionCeilingBreach, seg.Name, map[string]any{
					"oldest_ingest_millis": seg.FirstIngestMillis,
					"hot_max_ms":           m.cfg.Policy.HotMax.Milliseconds(),
				})
			}
		}
	}
}

func (m *Manager) writeCheckpoint() error {
	return WriteCheckpoint(m.cfg.CheckpointPath, m.cp, m.cfg.Signer)
}

func (m *Manager) emit(action, resource string, payload map[string]any) {
	if m.cfg.Emit != nil {
		m.cfg.Emit(action, resource, payload)
	}
}
