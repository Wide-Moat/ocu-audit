// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package fanout

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-audit/internal/ocsf"
	"github.com/Wide-Moat/ocu-audit/internal/store"
	"github.com/Wide-Moat/ocu-audit/internal/wal"
)

// C2 remainder (component-07 P7-D1, NFR-REL-12): the SIEM-side fan-out is
// DECOUPLED — a failing or slow sink never blocks admission — and replays
// from the store on recovery via a durable cursor. The transport stays
// unpinned (#150): a Sink interface plus the file reference, nothing more.
// Delivery is at-least-once; a cursor lagging past the rotation boundary is
// a PERMANENT sink gap, counted and evidenced, never a reason to hold
// rotation hostage to sink health.

// failSink fails until healed, recording everything emitted.
type failSink struct {
	healed bool
	got    []*ocsf.Record
}

var errSinkDown = errors.New("sink down")

func (s *failSink) Emit(rec *ocsf.Record) error {
	if !s.healed {
		return errSinkDown
	}
	s.got = append(s.got, rec)
	return nil
}

func newPumpRig(t *testing.T) (*store.Store, *failSink, *Pump, string) {
	t.Helper()
	dir := t.TempDir()
	w, err := wal.Open(filepath.Join(dir, "audit.wal"))
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(w, pumpClock{})
	t.Cleanup(func() { _ = st.Close() })
	sink := &failSink{}
	cursorPath := filepath.Join(dir, "fanout-cursor.json")
	pump := NewPump(st, sink, cursorPath, nil)
	return st, sink, pump, cursorPath
}

type pumpClock struct{}

func (pumpClock) NowMillis() int64 { return 0 }

func penv(seq uint64) *ocsf.PublishEnvelope {
	return &ocsf.PublishEnvelope{
		TraceID: "t", SessionID: "s", ActorID: "a",
		Resource: "r", Action: "act", Outcome: ocsf.OutcomeSuccess,
		Sequence: seq, Payload: json.RawMessage(`{}`),
	}
}

// TestAdmissionUnaffectedBySinkFailureThenDrain is the keystone. Every admit
// succeeds while the sink is down (the decoupling); the lag is visible; a
// healed sink drains EXACTLY the committed records in commit order.
func TestAdmissionUnaffectedBySinkFailureThenDrain(t *testing.T) {
	st, sink, pump, _ := newPumpRig(t)

	for seq := uint64(1); seq <= 5; seq++ {
		if _, err := st.Admit("control-plane", penv(seq)); err != nil {
			t.Fatalf("admit %d with the sink down: %v — a sink failure reached admission", seq, err)
		}
	}
	pump.RunOnce()
	if got := len(sink.got); got != 0 {
		t.Fatalf("a down sink received %d records", got)
	}
	if lag := pump.Lag(); lag != 5 {
		t.Fatalf("lag = %d with 5 committed and 0 delivered, want 5", lag)
	}

	sink.healed = true
	pump.RunOnce()
	if got := len(sink.got); got != 5 {
		t.Fatalf("healed sink drained %d records, want 5", got)
	}
	for i, rec := range sink.got {
		if rec.Sequence != uint64(i+1) {
			t.Fatalf("drained record %d has sequence %d; commit order broke", i, rec.Sequence)
		}
	}
	if lag := pump.Lag(); lag != 0 {
		t.Fatalf("lag = %d after a full drain, want 0", lag)
	}
}

// TestCursorSurvivesRestart: a new pump over the same cursor file resumes
// where the old one stopped — no re-delivery of drained records, and records
// committed between generations fan out.
func TestCursorSurvivesRestart(t *testing.T) {
	st, sink, pump, cursorPath := newPumpRig(t)
	sink.healed = true

	for seq := uint64(1); seq <= 3; seq++ {
		if _, err := st.Admit("control-plane", penv(seq)); err != nil {
			t.Fatal(err)
		}
	}
	pump.RunOnce()
	if len(sink.got) != 3 {
		t.Fatalf("precondition: drained %d, want 3", len(sink.got))
	}

	// Records committed after the drain, before the "restart".
	for seq := uint64(4); seq <= 5; seq++ {
		if _, err := st.Admit("control-plane", penv(seq)); err != nil {
			t.Fatal(err)
		}
	}

	// The restart: a fresh sink and pump over the SAME store and cursor file.
	sink2 := &failSink{healed: true}
	pump2 := NewPump(st, sink2, cursorPath, nil)
	pump2.RunOnce()
	if got := len(sink2.got); got != 2 {
		t.Fatalf("post-restart pump delivered %d records, want exactly the 2 undelivered "+
			"(a re-delivery means the cursor did not persist; a miss means replay is broken)", got)
	}
	if sink2.got[0].Sequence != 4 || sink2.got[1].Sequence != 5 {
		t.Fatalf("post-restart delivery out of order: %d, %d", sink2.got[0].Sequence, sink2.got[1].Sequence)
	}
}

// TestCursorAdvancesOnlyOnDeliverySuccess: a sink that fails MID-drain keeps
// the cursor at the last delivered record, so the failed record retries
// (at-least-once) rather than being skipped.
func TestCursorAdvancesOnlyOnDeliverySuccess(t *testing.T) {
	st, _, pump, cursorPath := newPumpRig(t)
	for seq := uint64(1); seq <= 3; seq++ {
		if _, err := st.Admit("control-plane", penv(seq)); err != nil {
			t.Fatal(err)
		}
	}
	// A sink that accepts exactly one record then fails.
	one := &quotaSink{quota: 1}
	pumpQ := NewPump(st, one, cursorPath, nil)
	pumpQ.RunOnce()
	if len(one.got) != 1 {
		t.Fatalf("quota sink took %d records, want 1", len(one.got))
	}
	_ = pump
	// Heal (unlimited quota): the remaining two deliver, nothing re-delivers.
	one.quota = 100
	pumpQ.RunOnce()
	if len(one.got) != 3 {
		t.Fatalf("after healing, sink holds %d records, want 3", len(one.got))
	}
	if one.got[1].Sequence != 2 {
		t.Fatalf("the failed record was skipped: second delivery is sequence %d, want 2", one.got[1].Sequence)
	}
}

type quotaSink struct {
	quota int
	got   []*ocsf.Record
}

func (s *quotaSink) Emit(rec *ocsf.Record) error {
	if len(s.got) >= s.quota {
		return errSinkDown
	}
	s.got = append(s.got, rec)
	return nil
}

// TestRotationGapIsCountedAndEvidenced: a cursor lagging past the rotation
// boundary has PERMANENTLY missed those records at the sink (the cold tier
// still holds them). The pump advances to the boundary, counts the gap, and
// self-emits gap evidence exactly once — it neither stalls forever nor
// silently pretends delivery.
func TestRotationGapIsCountedAndEvidenced(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "audit.wal")
	w, err := wal.Open(active)
	if err != nil {
		t.Fatal(err)
	}
	gen1 := store.New(w, pumpClock{})
	for seq := uint64(1); seq <= 3; seq++ {
		if _, err := gen1.Admit("control-plane", penv(seq)); err != nil {
			t.Fatal(err)
		}
	}
	// Anchored restart with the 3 records rotated away: globalOffset 3, hot empty.
	segName := wal.SegmentName(1)
	snap, err := gen1.SealActive(filepath.Join(dir, segName))
	if err != nil {
		t.Fatal(err)
	}
	if err := gen1.Close(); err != nil {
		t.Fatal(err)
	}
	coldDir := t.TempDir()
	if err := os.Rename(filepath.Join(dir, segName), filepath.Join(coldDir, segName)); err != nil {
		t.Fatal(err)
	}
	tips := map[string]store.ChainTip{}
	for src, tip := range snap.Tips {
		tips[src] = tip
	}
	gen2, err := store.RecoverAnchored(active, pumpClock{}, store.BootAnchor{
		ChainTips: tips, TreeSize: snap.TreeSize, Frontier: snap.Frontier,
		RotatedSegments: []string{segName}, IngestFloor: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gen2.Close() })

	var evidence []string
	sink := &failSink{healed: true}
	pump := NewPump(gen2, sink, filepath.Join(dir, "fanout-cursor.json"),
		func(action, resource string, payload map[string]any) {
			evidence = append(evidence, action+":"+resource)
		})
	pump.RunOnce()
	pump.RunOnce() // the evidence must not re-fire

	if got := pump.GapTotal(); got != 3 {
		t.Fatalf("gap total = %d, want 3 (the rotated records the sink never saw)", got)
	}
	if len(evidence) != 1 || !strings.Contains(evidence[0], ActionFanoutGap) {
		t.Fatalf("gap evidence = %v, want exactly one %s record", evidence, ActionFanoutGap)
	}
	// New admits after the gap fan out normally.
	if _, err := gen2.Admit("control-plane", penv(4)); err != nil {
		t.Fatal(err)
	}
	pump.RunOnce()
	if len(sink.got) != 1 || sink.got[0].Sequence != 4 {
		t.Fatalf("post-gap delivery wrong: %+v", sink.got)
	}
}

// TestFileSinkAppendsDecodableLines: the reference sink writes one JSON line
// per record, readable back — the solo-shelf collector contract.
func TestFileSinkAppendsDecodableLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fanout.jsonl")
	sink, err := NewFileSink(path)
	if err != nil {
		t.Fatal(err)
	}
	rec := &ocsf.Record{Source: "control-plane", Sequence: 9, Action: "act"}
	if err := sink.Emit(rec); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got ocsf.Record
	if err := json.Unmarshal(raw[:len(raw)-1], &got); err != nil {
		t.Fatalf("sink line does not decode: %v", err)
	}
	if got.Source != "control-plane" || got.Sequence != 9 {
		t.Fatalf("decoded %+v", got)
	}
}
