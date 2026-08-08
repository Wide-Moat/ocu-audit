// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Wide-Moat/ocu-audit/internal/merkletree"
	"github.com/Wide-Moat/ocu-audit/internal/ocsf"
	"github.com/Wide-Moat/ocu-audit/internal/wal"
)

// ADR-0045 stage 2 keystone: after a segment rotates to cold, boot recovers
// from the HOT tier plus the checkpoint anchor only — never reading the cold
// directory — and the recovered store continues the SAME tree and chains the
// uninterrupted store carried. Every head/size expectation below anchors on
// state captured from the PRE-rotation store, so a self-consistent-but-wrong
// recovery cannot green these.

// anchoredRig admits five records across a seal, simulates a completed
// rotation of segment 1 (moved to cold), and returns everything the keystone
// needs.
type anchoredRig struct {
	activePath string
	coldDir    string
	anchor     BootAnchor
	// Captured from the pre-rotation store (the subject the recovered store
	// must match):
	wantHead []byte
	wantSize uint64
	// The cold segment's records, for the test-side whole-union check.
	coldRecords []*ocsf.Record
}

func newAnchoredRig(t *testing.T) *anchoredRig {
	t.Helper()
	hotDir, coldDir := t.TempDir(), t.TempDir()
	active := filepath.Join(hotDir, "audit.wal")

	w, err := wal.Open(active)
	if err != nil {
		t.Fatal(err)
	}
	gen1 := New(w, &fakeClock{times: []int64{1000, 2000, 2500, 3000, 4000, 5000}})
	admit := func(src string, seq uint64) {
		t.Helper()
		if _, err := gen1.Admit(src, env(seq)); err != nil {
			t.Fatalf("admit %s/%d: %v", src, seq, err)
		}
	}
	// Segment 1 (rotates): control-plane 1,2 + object-store 1 + egress-edge 1.
	// egress-edge goes QUIET after the rotated prefix: with no hot record, only
	// the anchored tip can span its sequence and chain state — a hot-only
	// rebuild has nothing to catch its replays or link its next admit.
	admit("control-plane", 1)
	admit("object-store", 1)
	admit("egress-edge", 1)
	admit("control-plane", 2)
	segName := wal.SegmentName(1)
	if _, _, err := gen1.SealActive(filepath.Join(hotDir, segName)); err != nil {
		t.Fatal(err)
	}
	// Hot remainder: object-store 2, control-plane 3.
	admit("object-store", 2)
	admit("control-plane", 3)

	wantHead, wantSize, err := gen1.Head()
	if err != nil {
		t.Fatal(err)
	}

	// Build the anchor EXACTLY as the rotation manager will: from the first
	// four committed records (the rotated prefix).
	pre := gen1.Records()[:4]
	acc := merkletree.New()
	tips := map[string]ChainTip{}
	var floor int64
	for _, r := range pre {
		if err := acc.AppendLeaf(r.ChainHash); err != nil {
			t.Fatal(err)
		}
		tips[r.Source] = ChainTip{Hash: r.ChainHash, Seq: r.Sequence}
		if r.IngestTime > floor {
			floor = r.IngestTime
		}
	}
	treeSize, frontier := acc.Frontier()

	coldRecs := append([]*ocsf.Record(nil), pre...)
	if err := gen1.Close(); err != nil {
		t.Fatal(err)
	}
	// The completed rotation: the segment lives in cold, not hot.
	if err := os.Rename(filepath.Join(hotDir, segName), filepath.Join(coldDir, segName)); err != nil {
		t.Fatal(err)
	}

	return &anchoredRig{
		activePath: active,
		coldDir:    coldDir,
		anchor: BootAnchor{
			ChainTips:       tips,
			TreeSize:        treeSize,
			Frontier:        frontier,
			RotatedSegments: []string{segName},
			IngestFloor:     floor,
		},
		wantHead:    wantHead,
		wantSize:    wantSize,
		coldRecords: coldRecs,
	}
}

func TestRecoverAnchoredContinuesTreeAndChains(t *testing.T) {
	r := newAnchoredRig(t)

	gen2, err := RecoverAnchored(r.activePath, &fakeClock{times: []int64{6000}}, r.anchor)
	if err != nil {
		t.Fatalf("anchored recover: %v", err)
	}
	t.Cleanup(func() { _ = gen2.Close() })

	// Hot-only record set: exactly the two post-rotation records.
	recs := gen2.Records()
	if len(recs) != 2 || recs[0].Source != "object-store" || recs[0].Sequence != 2 ||
		recs[1].Source != "control-plane" || recs[1].Sequence != 3 {
		t.Fatalf("recovered hot set wrong: %+v", recs)
	}

	// SUBJECT BINDING: the continued head/size equal the PRE-rotation store's.
	gotHead, gotSize, err := gen2.Head()
	if err != nil {
		t.Fatal(err)
	}
	if gotSize != r.wantSize || !bytes.Equal(gotHead, r.wantHead) {
		t.Fatalf("anchored recovery head (%x, %d) != pre-rotation head (%x, %d) — "+
			"the frontier did not continue the same tree", gotHead, gotSize, r.wantHead, r.wantSize)
	}

	// Fresh admits continue both chains onto their tips.
	if _, err := gen2.Admit("control-plane", env(4)); err != nil {
		t.Fatalf("post-boot admit control-plane/4: %v", err)
	}
	if _, err := gen2.Admit("object-store", env(3)); err != nil {
		t.Fatalf("post-boot admit object-store/3: %v", err)
	}

	// WHOLE-UNION check from the test side (the daemon never does this; the
	// offline verifier owns it): cold records + hot records verify from
	// genesis, and the recomputed union head equals the live head.
	union := append(append([]*ocsf.Record(nil), r.coldRecords...), gen2.Records()...)
	if _, err := VerifyChainsFromRaw(union); err != nil {
		t.Fatalf("whole union does not verify from genesis after anchored boot + admits: %v", err)
	}
	unionHead, err := RecomputeHead(union)
	if err != nil {
		t.Fatal(err)
	}
	liveHead, liveSize, err := gen2.Head()
	if err != nil {
		t.Fatal(err)
	}
	if liveSize != uint64(len(union)) || !bytes.Equal(unionHead, liveHead) {
		t.Fatalf("live head (%x, %d) != recomputed union head (%x, %d)", liveHead, liveSize, unionHead, len(union))
	}
}

func TestRecoverAnchoredRefusesRotatedSequenceReplay(t *testing.T) {
	r := newAnchoredRig(t)
	gen2, err := RecoverAnchored(r.activePath, &fakeClock{times: []int64{6000}}, r.anchor)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gen2.Close() })

	// control-plane seq 1 lives ONLY in the rotated cold segment. Its replay
	// must be refused as a sequence regression by the ANCHORED tip — never
	// admitted as a fresh genesis-anchored fork.
	_, err = gen2.Admit("control-plane", env(1))
	if !errors.Is(err, ErrSequenceRegressed) {
		t.Fatalf("rotated-sequence replay returned %v, want ErrSequenceRegressed — "+
			"the anchored tip does not span the rotated prefix", err)
	}

	// The QUIET source: egress-edge has NO hot record, so only the seeded
	// anchored tip can refuse its rotated replay...
	_, err = gen2.Admit("egress-edge", env(1))
	if !errors.Is(err, ErrSequenceRegressed) {
		t.Fatalf("quiet-source rotated replay returned %v, want ErrSequenceRegressed — "+
			"tips are rebuilt from hot records only, not the anchor", err)
	}
	// ...and only the seeded tip HASH can make its next admit link onto the
	// rotated chain rather than re-anchoring on genesis. The union check in
	// the keystone test reds a genesis re-anchor; here the admit must simply
	// succeed with a strictly-greater sequence.
	if _, err := gen2.Admit("egress-edge", env(2)); err != nil {
		t.Fatalf("quiet-source next admit: %v", err)
	}
}

func TestRecoverAnchoredServesHotProofsAtGlobalIndexes(t *testing.T) {
	r := newAnchoredRig(t)
	gen2, err := RecoverAnchored(r.activePath, &fakeClock{times: []int64{6000}}, r.anchor)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gen2.Close() })

	head, size, err := gen2.Head()
	if err != nil {
		t.Fatal(err)
	}
	// Hot record 0 sits at GLOBAL index 4 (four rotated records precede it).
	prf, leafChainHash, err := gen2.InclusionProof(4)
	if err != nil {
		t.Fatalf("inclusion proof for global index 4: %v", err)
	}
	if err := merkletree.VerifyInclusion(4, size, leafChainHash, head, prf); err != nil {
		t.Fatalf("hot proof at global index 4 does not verify: %v", err)
	}
	// A rotated (cold) index is the offline verifier's job: refused, not wrong.
	if _, _, err := gen2.InclusionProof(0); err == nil {
		t.Fatal("a proof for a rotated (cold) index was served from the hot-only store; " +
			"it cannot have the pre-frontier nodes and must refuse")
	}
}

func TestRecoverAnchoredExcludesRotatedButPresentSegment(t *testing.T) {
	r := newAnchoredRig(t)
	// The crash-before-removal state: the rotated segment ALSO still present
	// in hot. Boot must exclude it (the checkpoint says rotated), not
	// double-count its records.
	segName := r.anchor.RotatedSegments[0]
	if err := copyFile(filepath.Join(r.coldDir, segName), filepath.Join(filepath.Dir(r.activePath), segName)); err != nil {
		t.Fatal(err)
	}

	gen2, err := RecoverAnchored(r.activePath, &fakeClock{times: []int64{6000}}, r.anchor)
	if err != nil {
		t.Fatalf("anchored recover with a pending-removal segment: %v", err)
	}
	t.Cleanup(func() { _ = gen2.Close() })

	if got := len(gen2.Records()); got != 2 {
		t.Fatalf("recovered %d hot records, want 2 — the rotated-but-present segment "+
			"was double-counted", got)
	}
	gotHead, gotSize, err := gen2.Head()
	if err != nil {
		t.Fatal(err)
	}
	if gotSize != r.wantSize || !bytes.Equal(gotHead, r.wantHead) {
		t.Fatal("head diverged when a rotated segment was still present in hot")
	}
}

func TestRecoverAnchoredRestoresIngestFloor(t *testing.T) {
	r := newAnchoredRig(t)
	// Clock rolled back to 42 after restart; the anchor floor (3000, from the
	// rotated prefix) and the hot records' stamps (4000, 5000) must both hold
	// the floor at 5000.
	gen2, err := RecoverAnchored(r.activePath, &fakeClock{times: []int64{42}}, r.anchor)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gen2.Close() })

	rec, err := gen2.Admit("control-plane", env(4))
	if err != nil {
		t.Fatal(err)
	}
	if rec.IngestTime < 5000 {
		t.Fatalf("post-anchored-boot IngestTime = %d, below the hot floor 5000; "+
			"a rollback across an anchored restart backdated the trusted stamp", rec.IngestTime)
	}
}

// TestRecoverAnchoredFloorHoldsWithEmptyHot: every record rotated, the active
// file empty — the anchor floor is the ONLY floor, so a clock rollback across
// the restart can only be caught by seeding it from the anchor.
func TestRecoverAnchoredFloorHoldsWithEmptyHot(t *testing.T) {
	hotDir, coldDir := t.TempDir(), t.TempDir()
	active := filepath.Join(hotDir, "audit.wal")
	w, err := wal.Open(active)
	if err != nil {
		t.Fatal(err)
	}
	gen1 := New(w, &fakeClock{times: []int64{7000}})
	if _, err := gen1.Admit("control-plane", env(1)); err != nil {
		t.Fatal(err)
	}
	segName := wal.SegmentName(1)
	if _, _, err := gen1.SealActive(filepath.Join(hotDir, segName)); err != nil {
		t.Fatal(err)
	}
	rec := gen1.Records()[0]
	acc := merkletree.New()
	if err := acc.AppendLeaf(rec.ChainHash); err != nil {
		t.Fatal(err)
	}
	size, frontier := acc.Frontier()
	if err := gen1.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(hotDir, segName), filepath.Join(coldDir, segName)); err != nil {
		t.Fatal(err)
	}

	anchor := BootAnchor{
		ChainTips:       map[string]ChainTip{"control-plane": {Hash: rec.ChainHash, Seq: 1}},
		TreeSize:        size,
		Frontier:        frontier,
		RotatedSegments: []string{segName},
		IngestFloor:     7000,
	}
	// Restart with the clock rolled back to 10.
	gen2, err := RecoverAnchored(active, &fakeClock{times: []int64{10}}, anchor)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gen2.Close() })
	got, err := gen2.Admit("control-plane", env(2))
	if err != nil {
		t.Fatal(err)
	}
	if got.IngestTime < 7000 {
		t.Fatalf("empty-hot anchored boot stamped IngestTime %d, below the anchor floor "+
			"7000 — the rotated prefix's floor was not restored (NFR-SEC-48)", got.IngestTime)
	}
}

// TestRecoverAnchoredRefusesMismatchedTip: an anchor whose chain tip does not
// match what the first hot record links onto must refuse boot — this is the
// linkage check that makes the anchor LOAD-BEARING. Without it, a forged
// checkpoint could splice an arbitrary prefix under the hot tier.
func TestRecoverAnchoredRefusesMismatchedTip(t *testing.T) {
	r := newAnchoredRig(t)
	bad := r.anchor
	badTips := map[string]ChainTip{}
	for src, tip := range r.anchor.ChainTips {
		h := append([]byte(nil), tip.Hash...)
		badTips[src] = ChainTip{Hash: h, Seq: tip.Seq}
	}
	flip := badTips["object-store"]
	flip.Hash[0] ^= 0x01
	badTips["object-store"] = flip
	bad.ChainTips = badTips

	if _, err := RecoverAnchored(r.activePath, &fakeClock{times: []int64{6000}}, bad); err == nil {
		t.Fatal("anchored boot accepted a hot tier that does not link onto the anchor's " +
			"chain tip; the checkpoint anchor is decorative, not load-bearing")
	}
}
