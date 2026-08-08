// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package edgetail

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Wide-Moat/ocu-audit/internal/ocsf"
)

// The tailer is the durable at-least-once bridge from the Envoy access log to
// the fan-in: a cursor file carries {offset, sequence} across restarts, so a
// restarted tailer neither re-publishes delivered lines nor regresses its
// per-source sequence (a regressed publish is refused by the pipeline and the
// connection record silently lost — the SelfEmit restart lesson, designed in
// from the start here).

type capturePub struct {
	failing bool
	got     []*ocsf.PublishEnvelope
}

var errPubDown = errors.New("publisher down")

func (p *capturePub) Publish(_ context.Context, env *ocsf.PublishEnvelope) error {
	if p.failing {
		return errPubDown
	}
	p.got = append(p.got, env)
	return nil
}

func writeLog(t *testing.T, path string, lines ...string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range lines {
		if _, err := f.WriteString(l + "\n"); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func entry(reqID string) string {
	return fmt.Sprintf(`{"start_time":"2026-08-08T10:00:00Z","method":"GET","path":"/p","authority":"up:1","response_code":200,"response_code_details":"via_upstream","bytes_sent":1,"bytes_received":0,"duration_ms":1,"x_request_id":%q,"session_id":"s"}`, reqID)
}

func newTailRig(t *testing.T) (string, string, *capturePub, *Tailer) {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "edge-access.log")
	cursorPath := filepath.Join(dir, "edgetail-cursor.json")
	pub := &capturePub{}
	return logPath, cursorPath, pub, NewTailer(logPath, cursorPath, pub)
}

func TestTailPublishesLinesInOrder(t *testing.T) {
	logPath, _, pub, tl := newTailRig(t)
	writeLog(t, logPath, entry("r1"), entry("r2"), entry("r3"))

	tl.RunOnce(context.Background())
	if len(pub.got) != 3 {
		t.Fatalf("published %d, want 3", len(pub.got))
	}
	for i, env := range pub.got {
		if env.TraceID != fmt.Sprintf("r%d", i+1) {
			t.Fatalf("publish %d = %q; log order broke", i, env.TraceID)
		}
		if env.Sequence != uint64(i+1) {
			t.Fatalf("publish %d sequence = %d, want %d (strictly monotonic from 1)", i, env.Sequence, i+1)
		}
	}
	// Idempotent: a second run with no new lines publishes nothing.
	tl.RunOnce(context.Background())
	if len(pub.got) != 3 {
		t.Fatalf("re-run re-published (%d total); the cursor did not advance", len(pub.got))
	}
}

// TestTailResumesAcrossRestartWithoutSequenceRegression is the keystone: a
// NEW tailer over the same cursor file picks up exactly the undelivered lines
// AND continues the sequence — a restart that re-minted sequence 1 would be
// refused by the pipeline's monotonicity gate and the records silently lost.
func TestTailResumesAcrossRestartWithoutSequenceRegression(t *testing.T) {
	logPath, cursorPath, pub, tl := newTailRig(t)
	writeLog(t, logPath, entry("r1"), entry("r2"))
	tl.RunOnce(context.Background())
	if len(pub.got) != 2 {
		t.Fatalf("precondition: %d", len(pub.got))
	}

	writeLog(t, logPath, entry("r3"))
	pub2 := &capturePub{}
	tl2 := NewTailer(logPath, cursorPath, pub2)
	tl2.RunOnce(context.Background())

	if len(pub2.got) != 1 || pub2.got[0].TraceID != "r3" {
		t.Fatalf("post-restart published %+v, want exactly r3", pub2.got)
	}
	if pub2.got[0].Sequence != 3 {
		t.Fatalf("post-restart sequence = %d, want 3 — a restarted tailer regressed "+
			"its sequence and the pipeline would refuse the publish", pub2.got[0].Sequence)
	}
}

// TestTailLeavesTornLineForNextRun: a line without a trailing newline is a
// write in progress — untouched this run, published complete next run.
func TestTailLeavesTornLineForNextRun(t *testing.T) {
	logPath, _, pub, tl := newTailRig(t)
	writeLog(t, logPath, entry("r1"))
	// A torn tail: no trailing newline.
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	torn := entry("r2")
	if _, err := f.WriteString(torn[:20]); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	tl.RunOnce(context.Background())
	if len(pub.got) != 1 {
		t.Fatalf("published %d with a torn tail, want 1 — the torn line must wait", len(pub.got))
	}

	// The write completes; the next run publishes it whole.
	f, err = os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(torn[20:] + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	tl.RunOnce(context.Background())
	if len(pub.got) != 2 || pub.got[1].TraceID != "r2" {
		t.Fatalf("completed torn line not published whole: %+v", pub.got)
	}
}

// TestTailRetriesOnPublisherFailure: at-least-once — a refused publish keeps
// the cursor, and the healed publisher receives the SAME line with the SAME
// sequence (a fresh sequence for a retry would double-count the connection).
func TestTailRetriesOnPublisherFailure(t *testing.T) {
	logPath, _, pub, tl := newTailRig(t)
	writeLog(t, logPath, entry("r1"))

	pub.failing = true
	tl.RunOnce(context.Background())
	if len(pub.got) != 0 {
		t.Fatal("a failing publisher received a record")
	}
	pub.failing = false
	tl.RunOnce(context.Background())
	if len(pub.got) != 1 || pub.got[0].Sequence != 1 {
		t.Fatalf("retry after heal: %+v, want r1 at sequence 1", pub.got)
	}
}

// TestTailSkipsGarbageCounted: a malformed line is skipped and counted, the
// good lines around it still publish — a poisoned line must not wedge the
// bridge forever, and the skip count is the operator's drift signal.
func TestTailSkipsGarbageCounted(t *testing.T) {
	logPath, _, pub, tl := newTailRig(t)
	writeLog(t, logPath, entry("r1"), "not json", entry("r2"))

	tl.RunOnce(context.Background())
	if len(pub.got) != 2 {
		t.Fatalf("published %d around a garbage line, want 2", len(pub.got))
	}
	if got := tl.Skipped(); got != 1 {
		t.Fatalf("skipped = %d, want 1", got)
	}
	// Sequences stay contiguous for what WAS published.
	if pub.got[0].Sequence != 1 || pub.got[1].Sequence != 2 {
		t.Fatalf("sequences %d,%d; a skipped line must not burn a sequence number",
			pub.got[0].Sequence, pub.got[1].Sequence)
	}
}

// TestTailHandlesRotationReset: the log file shrank (rotated/truncated) — the
// tailer restarts from offset 0 rather than seeking past the end forever.
func TestTailHandlesRotationReset(t *testing.T) {
	logPath, _, pub, tl := newTailRig(t)
	writeLog(t, logPath, entry("r1"), entry("r2"))
	tl.RunOnce(context.Background())

	// Rotation: the file is replaced by a shorter one.
	if err := os.WriteFile(logPath, []byte(entry("r3")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tl.RunOnce(context.Background())
	if len(pub.got) != 3 || pub.got[2].TraceID != "r3" {
		t.Fatalf("after rotation: %+v, want r3 delivered", pub.got)
	}
	if pub.got[2].Sequence != 3 {
		t.Fatalf("post-rotation sequence = %d, want 3 (rotation resets the offset, "+
			"never the sequence)", pub.got[2].Sequence)
	}
}
