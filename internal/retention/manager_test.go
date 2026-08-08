// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package retention

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"encoding/json"

	"github.com/Wide-Moat/ocu-audit/internal/ocsf"
	"github.com/Wide-Moat/ocu-audit/internal/signer"
	"github.com/Wide-Moat/ocu-audit/internal/store"
	"github.com/Wide-Moat/ocu-audit/internal/wal"
)

// The Manager is the rotation loop as a TESTABLE OBJECT: Tick(now) runs one
// seal/rotate/breach round, driven here directly with scripted times — never
// an anonymous goroutine a test cannot reach. Failure posture (ADR-0045):
// rotation failure never propagates anywhere near admission; it self-emits
// chain-linked evidence and retries on a later tick.

// managerRig assembles a Manager over temp dirs with fake seams.
type managerRig struct {
	m        *Manager
	hotDir   string
	coldDir  string
	cpDir    string
	sealMade []string // sealed paths the fake Seal seam produced
	emits    []emitRecord
	// currentCount is what the CurrentCount seam reports (global committed).
	currentCount uint64
	// sealSnap is returned by the fake Seal seam.
	sealSnap SealSnapshot
	t        *testing.T
}

type emitRecord struct {
	action, resource string
}

// SealSnapshot mirrors store.SealSnapshot without importing store.
// (Defined in manager.go; used here for the fake seam.)

func newManagerRig(t *testing.T) *managerRig {
	t.Helper()
	hotDir, coldDir := t.TempDir(), t.TempDir()
	sgn, err := signer.Generate()
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewPolicy(7, 2160*time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cpDir := t.TempDir()
	rig := &managerRig{hotDir: hotDir, coldDir: coldDir, cpDir: cpDir, t: t}
	rig.sealSnap = SealSnapshot{
		Count: 1, TreeSize: 1,
		Frontier: [][]byte{bytes.Repeat([]byte{0x0A}, 32)},
		Tips:     map[string]store.ChainTip{"control-plane": {Hash: bytes.Repeat([]byte{0x0B}, 32), Seq: 1}},
	}
	m, err := NewManager(ManagerConfig{
		Policy:         p,
		HotDir:         hotDir,
		ColdDir:        coldDir,
		CheckpointPath: filepath.Join(cpDir, "retention-checkpoint.json"),
		Signer:         sgn,
		CurrentCount:   func() uint64 { return rig.currentCount },
		Seal: func(sealedPath string) (SealSnapshot, error) {
			// A real segment file appears at the sealed path (the WAL rename).
			if err := os.WriteFile(sealedPath, sealedSegmentBytes(t), 0o600); err != nil {
				return SealSnapshot{}, err
			}
			rig.sealMade = append(rig.sealMade, sealedPath)
			return rig.sealSnap, nil
		},
		Emit: func(action, resource string, _ map[string]any) {
			rig.emits = append(rig.emits, emitRecord{action: action, resource: resource})
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	rig.m = m
	return rig
}

// sealedSegmentBytes builds a real sealed segment: two committed ocsf
// records (IngestTime stamped near zero by the scripted clock), so the
// manager's inventory pass decodes them and the segment's oldest-ingest
// baseline sits at ~0 for the literal-time rotation assertions.
func sealedSegmentBytes(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	active := filepath.Join(dir, "audit.wal")
	w, err := wal.Open(active)
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(w, zeroTickClock{})
	for seq := uint64(1); seq <= 2; seq++ {
		if _, err := st.Admit("control-plane", testEnv(seq)); err != nil {
			t.Fatal(err)
		}
	}
	seg := filepath.Join(dir, wal.SegmentName(1))
	if err := w.SealTo(seg); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(seg)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// zeroTickClock stamps IngestTime 0 so segment ages count from the epoch the
// literal-time tests assume.
type zeroTickClock struct{}

func (zeroTickClock) NowMillis() int64 { return 0 }

// testEnv builds a minimal publish envelope.
func testEnv(seq uint64) *ocsf.PublishEnvelope {
	return &ocsf.PublishEnvelope{
		TraceID: "t", SessionID: "s", ActorID: "a",
		Resource: "r", Action: "act", Outcome: ocsf.OutcomeSuccess,
		Sequence: seq, Payload: json.RawMessage(`{}`),
	}
}

func (r *managerRig) emitted(action string) int {
	n := 0
	for _, e := range r.emits {
		if e.action == action {
			n++
		}
	}
	return n
}

// TestTickSealsWhenDue: with unsealed records present, the first tick past
// the seal interval seals; a tick just under does not. Literal times.
func TestTickSealsWhenDue(t *testing.T) {
	r := newManagerRig(t)
	r.currentCount = 5 // records exist

	// Just under 24h since the (zero) epoch baseline: no seal.
	r.m.Tick((24*time.Hour - time.Second).Milliseconds())
	if len(r.sealMade) != 0 {
		t.Fatal("sealed before the seal interval elapsed")
	}
	r.m.Tick((24 * time.Hour).Milliseconds())
	if len(r.sealMade) != 1 {
		t.Fatalf("%d seals after the interval elapsed, want 1", len(r.sealMade))
	}
	// The checkpoint on disk records the sealed segment.
	cp := r.loadCheckpoint()
	if len(cp.Segments) != 1 || cp.Segments[0].RotatedAtMillis != 0 {
		t.Fatalf("checkpoint after seal: %+v", cp.Segments)
	}
	if cp.Segments[0].SealTreeSize != 1 || len(cp.Segments[0].SealFrontier) != 1 {
		t.Fatal("seal-point anchors not recorded on the segment entry")
	}
}

// TestTickDoesNotSealAnEmptyActive: no new records => no seal, however much
// time passes (an empty segment would be inventory noise).
func TestTickDoesNotSealAnEmptyActive(t *testing.T) {
	r := newManagerRig(t)
	r.currentCount = 0
	r.m.Tick((48 * time.Hour).Milliseconds())
	if len(r.sealMade) != 0 {
		t.Fatal("sealed an empty active file")
	}
}

func (r *managerRig) loadCheckpoint() Checkpoint {
	r.t.Helper()
	cp, err := LoadCheckpoint(filepath.Join(r.cpDir, "retention-checkpoint.json"),
		r.m.PublicKey(), r.m.ConfiguredPolicy())
	if err != nil {
		r.t.Fatalf("load checkpoint: %v", err)
	}
	return cp
}

// TestTickRotatesDueSegmentAndPromotesAnchors is the manager keystone: a
// sealed segment aged past the rotation threshold rotates on the next tick —
// the verified copy lands cold, the hot copy is removed, and the checkpoint's
// TOP-LEVEL anchors become the segment's seal-point anchors, in that order
// (checkpoint BEFORE hot removal, so a crash between them boots anchored with
// the segment excluded, never unanchored with it missing).
func TestTickRotatesDueSegmentAndPromotesAnchors(t *testing.T) {
	r := newManagerRig(t)
	r.currentCount = 5

	r.m.Tick((24 * time.Hour).Milliseconds()) // seals segment 1
	if len(r.sealMade) != 1 {
		t.Fatal("precondition: no seal")
	}
	segName := filepath.Base(r.sealMade[0])

	// Rotation threshold: HotMax(2160h) - SealInterval(24h) = 2136h after the
	// segment's oldest ingest (which the fake snapshot pins at 0... the entry
	// records FirstIngestMillis from the seal; our fake sets ingest bounds via
	// the checkpoint entry the manager writes from the actual segment file).
	r.m.Tick((2137 * time.Hour).Milliseconds())

	coldPath := filepath.Join(r.coldDir, segName)
	if _, err := os.Stat(coldPath); err != nil {
		t.Fatalf("cold copy absent after a due rotation: %v", err)
	}
	if _, err := os.Stat(filepath.Join(r.hotDir, segName)); !os.IsNotExist(err) {
		t.Fatal("hot copy still present after rotation completed")
	}
	cp := r.loadCheckpoint()
	if cp.Segments[0].RotatedAtMillis == 0 {
		t.Fatal("checkpoint does not mark the segment rotated")
	}
	if cp.TreeSize != 1 || len(cp.Frontier) != 1 || cp.ChainTips["control-plane"].Seq != 1 {
		t.Fatalf("top-level anchors not promoted from the seal snapshot: %+v", cp)
	}
}

// TestRotationFailureEmitsAndRetries: an unwritable cold dir fails the
// rotation; the tick survives, self-emits rotation-failure ONCE for the
// segment, leaves the hot copy intact, and does NOT advance the anchors. A
// later tick with the cold dir healed completes and emits nothing more.
func TestRotationFailureEmitsAndRetries(t *testing.T) {
	r := newManagerRig(t)
	r.currentCount = 2 // one segment only; see TestCeilingBreachEmitsOnce
	r.m.Tick((24 * time.Hour).Milliseconds())
	segName := filepath.Base(r.sealMade[0])

	if err := os.Chmod(r.coldDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(r.coldDir, 0o700) })

	r.m.Tick((2137 * time.Hour).Milliseconds())
	r.m.Tick((2138 * time.Hour).Milliseconds())
	if got := r.emitted(ActionRotationFailure); got != 1 {
		t.Fatalf("rotation-failure emitted %d times across two failing ticks, want 1 "+
			"(once per episode; the evidence channel must not flood)", got)
	}
	if _, err := os.Stat(filepath.Join(r.hotDir, segName)); err != nil {
		t.Fatal("hot copy lost during failed rotation")
	}
	cp := r.loadCheckpoint()
	if cp.TreeSize != 0 {
		t.Fatal("anchors advanced despite the rotation failing")
	}

	if err := os.Chmod(r.coldDir, 0o700); err != nil {
		t.Fatal(err)
	}
	r.m.Tick((2139 * time.Hour).Milliseconds())
	if _, err := os.Stat(filepath.Join(r.coldDir, segName)); err != nil {
		t.Fatal("rotation did not complete after the cold dir healed")
	}
	cp = r.loadCheckpoint()
	if cp.TreeSize != 1 {
		t.Fatal("anchors not promoted after the healed rotation")
	}
}

// TestCeilingBreachEmitsOnce: a segment stuck hot past the 90 d ceiling
// (rotation kept failing) emits the breach evidence exactly once per episode.
func TestCeilingBreachEmitsOnce(t *testing.T) {
	r := newManagerRig(t)
	// Exactly the sealed segment's record count: after the first seal the
	// boundary equals the count, so later ticks mint no fresh segments (a
	// fresh zero-stamped segment would instantly breach and double the emit).
	r.currentCount = 2
	r.m.Tick((24 * time.Hour).Milliseconds())
	if err := os.Chmod(r.coldDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(r.coldDir, 0o700) })

	// Past the ceiling itself (2160h from the segment's first ingest ~0).
	r.m.Tick((2161 * time.Hour).Milliseconds())
	r.m.Tick((2162 * time.Hour).Milliseconds())
	if got := r.emitted(ActionCeilingBreach); got != 1 {
		t.Fatalf("ceiling-breach emitted %d times, want exactly 1 per episode", got)
	}
}

// TestBootPolicySyncEmitsOnChange: a lengthened floor at boot emits the
// NFR-SEC-45 policy-change record and repins the checkpoint; an identical
// policy emits nothing.
func TestBootPolicySyncEmitsOnChange(t *testing.T) {
	r := newManagerRig(t)
	r.currentCount = 5
	r.m.Tick((24 * time.Hour).Milliseconds()) // creates the checkpoint

	if err := r.m.BootPolicySync(); err != nil {
		t.Fatalf("no-change sync: %v", err)
	}
	if got := r.emitted(ActionPolicyChange); got != 0 {
		t.Fatalf("policy-change emitted %d times with an unchanged policy", got)
	}

	longer, err := NewPolicy(10, 2160*time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	r.m.SetPolicyForTestOfBootSync(longer)
	if err := r.m.BootPolicySync(); err != nil {
		t.Fatalf("lengthen sync: %v", err)
	}
	if got := r.emitted(ActionPolicyChange); got != 1 {
		t.Fatalf("policy-change emitted %d times after a floor lengthening, want 1", got)
	}
	cp := r.loadCheckpointWith(longer)
	if cp.Policy.FloorYears != 10 {
		t.Fatal("checkpoint not repinned to the lengthened floor")
	}
}

func (r *managerRig) loadCheckpointWith(p Policy) Checkpoint {
	r.t.Helper()
	cp, err := LoadCheckpoint(filepath.Join(r.cpDir, "retention-checkpoint.json"),
		r.m.PublicKey(), p)
	if err != nil {
		r.t.Fatalf("load checkpoint: %v", err)
	}
	return cp
}

// errInjectedSeal proves a seal failure is surfaced, not swallowed.
func TestTickSurfacesSealFailure(t *testing.T) {
	r := newManagerRig(t)
	r.currentCount = 5
	wantErr := errors.New("seal exploded")
	r.m.cfg.Seal = func(string) (SealSnapshot, error) { return SealSnapshot{}, wantErr }
	r.m.Tick((24 * time.Hour).Milliseconds())
	if got := r.emitted(ActionSealFailure); got != 1 {
		t.Fatalf("a failed seal emitted %d seal-failure evidence records, want 1", got)
	}
}

// TestCheckpointFailureLeavesHotCopy binds the ADR-0045 rotation ordering:
// checkpoint BEFORE hot removal. When the checkpoint rewrite fails after a
// verified cold copy, the hot copy MUST survive — removing it first would
// leave the segment cold-only while the checkpoint still anchors before it,
// and the next boot would refuse or lose the suffix.
func TestCheckpointFailureLeavesHotCopy(t *testing.T) {
	r := newManagerRig(t)
	r.currentCount = 2
	r.m.Tick((24 * time.Hour).Milliseconds()) // seal + checkpoint OK
	segName := filepath.Base(r.sealMade[0])

	if err := os.Chmod(r.cpDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(r.cpDir, 0o700) })

	r.m.Tick((2137 * time.Hour).Milliseconds())

	if _, err := os.Stat(filepath.Join(r.hotDir, segName)); err != nil {
		t.Fatal("hot copy removed although the checkpoint rewrite failed; the " +
			"ordering is removal-before-checkpoint and a crash here strands the segment")
	}
	if got := r.emitted(ActionRotationFailure); got != 1 {
		t.Fatalf("checkpoint-failure rotation emitted %d evidence records, want 1", got)
	}
	// Heal and complete: the identical both-copies resume path finishes.
	if err := os.Chmod(r.cpDir, 0o700); err != nil {
		t.Fatal(err)
	}
	r.m.Tick((2138 * time.Hour).Milliseconds())
	if _, err := os.Stat(filepath.Join(r.hotDir, segName)); !os.IsNotExist(err) {
		t.Fatal("rotation did not complete after the checkpoint dir healed")
	}
	cp := r.loadCheckpoint()
	if cp.Segments[0].RotatedAtMillis == 0 || cp.TreeSize != 1 {
		t.Fatal("checkpoint not advanced after the healed retry")
	}
}
