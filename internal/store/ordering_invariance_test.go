// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package store

import (
	"encoding/json"
	"testing"

	"github.com/Wide-Moat/ocu-audit/internal/ocsf"
)

// INV-5 stage 1 (component-07, NFR-SEC-48): chain order derives from the
// per-source monotonic sequence, NOT wall-clock. The source-authored occurred-at
// time rides the OCSF payload, is recorded, but is never an ordering key and
// never gates admission.
//
// Today this holds by construction — the store reads only `sequence` and no
// wall-clock field feeds ordering or admission. "By construction" is a fact
// about the current code, not a guarantee about the next commit: the moment
// someone wires a payload time into admission or ordering, this test goes red.
// That is what the invariant guards.
//
// The property is stated as INVARIANCE: feed one sequence stream, then the SAME
// stream with the payload `time` adversarially mutated (rolled back, far-future,
// permuted across events), and require the admitted/rejected pattern, the
// storage order, and the sequence enforcement to be byte-for-byte identical.
// A clock a chain never reads cannot reorder it.

// timedEnv is env() plus an occurred-at time on the payload, the field a
// rollback attacker would target.
func timedEnv(seq uint64, occurredAt int64) *ocsf.PublishEnvelope {
	payload, _ := json.Marshal(map[string]any{"seq": seq, "time": occurredAt})
	return &ocsf.PublishEnvelope{
		TraceID: "t", SessionID: "s", ActorID: "a",
		Resource: "r", Action: "act", Outcome: ocsf.OutcomeSuccess,
		Sequence: seq, Payload: payload,
	}
}

// runOutcome is the observable result of admitting one stream: per-attempt
// admit/reject, and the resulting stored order by sequence.
type runOutcome struct {
	admitted []bool
	order    []uint64
}

func runStream(t *testing.T, seqs []uint64, times []int64) runOutcome {
	t.Helper()
	st, _ := newStore(t)
	var res runOutcome
	for i, seq := range seqs {
		_, err := st.Admit("control-plane", timedEnv(seq, times[i]))
		res.admitted = append(res.admitted, err == nil)
	}
	for _, r := range st.Records() {
		res.order = append(res.order, r.Sequence)
	}
	return res
}

func sameOutcome(a, b runOutcome) bool {
	if len(a.admitted) != len(b.admitted) || len(a.order) != len(b.order) {
		return false
	}
	for i := range a.admitted {
		if a.admitted[i] != b.admitted[i] {
			return false
		}
	}
	for i := range a.order {
		if a.order[i] != b.order[i] {
			return false
		}
	}
	return true
}

// TestOrderingIsWallClockInvariant is the keystone. The sequence stream is
// fixed; only the payload occurred-at times change between runs. Every
// observable — what was admitted, what was rejected, the stored order — must be
// identical, or a clock is leaking into a decision it must not touch.
func TestOrderingIsWallClockInvariant(t *testing.T) {
	// A stream with a genuine sequence regression in the middle: seq 2 then 2
	// again is the store's ErrSequenceRegressed case, so the admit/reject pattern
	// is non-trivial and a mutation that changed it would show.
	seqs := []uint64{1, 2, 2, 3}

	baseline := runStream(t, seqs, []int64{1000, 2000, 3000, 4000})

	for _, tc := range []struct {
		name  string
		times []int64
	}{
		// The occurred-at clock rolled backward: later events stamped earlier.
		{"rolled back", []int64{4000, 3000, 2000, 1000}},
		// A far-future stamp on one event.
		{"far future", []int64{1000, 1 << 40, 3000, 4000}},
		// Times permuted across events, decoupled from sequence entirely.
		{"permuted", []int64{3000, 1000, 4000, 2000}},
		// All identical — no time information at all.
		{"flat", []int64{0, 0, 0, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := runStream(t, seqs, tc.times)
			if !sameOutcome(baseline, got) {
				t.Errorf("mutating the payload occurred-at (%s) changed the admit/order "+
					"outcome:\n baseline admitted=%v order=%v\n got      admitted=%v order=%v\n"+
					"the chain is reading a wall-clock it must not (INV-5)",
					tc.name, baseline.admitted, baseline.order, got.admitted, got.order)
			}
		})
	}
}

// TestSequenceRegressionFiresRegardlessOfTime pins the specific admission gate:
// a non-increasing sequence is refused whatever the payload time says. A
// backdated OR future-dated regressing event must still be rejected — a clock
// must not be able to launder a replayed sequence past the monotonicity check.
func TestSequenceRegressionFiresRegardlessOfTime(t *testing.T) {
	st, _ := newStore(t)

	if _, err := st.Admit("control-plane", timedEnv(5, 5000)); err != nil {
		t.Fatalf("first admit: %v", err)
	}
	// Same sequence, but stamped far in the future — must still regress.
	_, err := st.Admit("control-plane", timedEnv(5, 1<<40))
	if err == nil {
		t.Fatal("a repeated sequence with a future timestamp was admitted; a clock " +
			"laundered a sequence-regression past the monotonicity gate")
	}
	// And stamped in the deep past — same verdict.
	if _, err := st.Admit("control-plane", timedEnv(5, 1)); err == nil {
		t.Fatal("a repeated sequence with a backdated timestamp was admitted")
	}
	// A strictly-greater sequence with a BACKDATED time is still admitted: order
	// follows sequence, and the older wall-clock does not block the newer event.
	if _, err := st.Admit("control-plane", timedEnv(6, 1)); err != nil {
		t.Fatalf("a strictly-greater sequence was refused because its time was old: %v — "+
			"ordering must follow sequence, not the clock", err)
	}
}

// TestStoredOrderFollowsSequenceNotArrivalTime keeps the stored order bound to
// sequence. Events admitted with descending occurred-at times still store in
// ascending sequence order.
func TestStoredOrderFollowsSequenceNotArrivalTime(t *testing.T) {
	st, _ := newStore(t)
	// Ascending sequences, descending occurred-at times.
	for i, seq := range []uint64{1, 2, 3} {
		if _, err := st.Admit("control-plane", timedEnv(seq, int64(9000-i*1000))); err != nil {
			t.Fatalf("admit seq %d: %v", seq, err)
		}
	}
	got := runOutcome{}
	for _, r := range st.Records() {
		got.order = append(got.order, r.Sequence)
	}
	want := []uint64{1, 2, 3}
	for i := range want {
		if got.order[i] != want[i] {
			t.Errorf("stored order %v, want %v — order followed arrival time, not sequence", got.order, want)
			break
		}
	}
}
