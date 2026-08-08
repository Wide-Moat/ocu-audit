// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package edgetail

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Wide-Moat/ocu-audit/internal/ocsf"
)

// Publisher is the fan-in seam the tailer delivers through — pkg/publish's
// Client in production, a capture fake in tests.
type Publisher interface {
	Publish(ctx context.Context, env *ocsf.PublishEnvelope) error
}

// cursorState is the durable position: the byte offset of the next unread
// line and the last sequence PUBLISHED. The sequence survives restarts and
// rotations — a re-minted sequence 1 would regress against the pipeline's
// monotonicity gate and the records would be silently refused.
type cursorState struct {
	Offset   int64  `json:"offset"`
	Sequence uint64 `json:"sequence"`
}

// Tailer bridges the Envoy access log to the egress-edge fan-in channel,
// one RunOnce per tick, single goroutine.
type Tailer struct {
	logPath    string
	cursorPath string
	pub        Publisher

	cur     cursorState
	skipped uint64
}

// NewTailer loads the cursor (absent = genesis) and returns the tailer.
func NewTailer(logPath, cursorPath string, pub Publisher) *Tailer {
	t := &Tailer{logPath: logPath, cursorPath: cursorPath, pub: pub}
	raw, err := os.ReadFile(cursorPath) // #nosec G304 -- daemon-owned cursor path
	if err == nil {
		_ = json.Unmarshal(raw, &t.cur)
	}
	return t
}

// Skipped returns the count of malformed lines skipped — the operator's
// format-drift signal.
func (t *Tailer) Skipped() uint64 { return t.skipped }

// RunOnce reads complete lines from the cursor offset and publishes each in
// order, advancing the durable cursor after every successful publish
// (at-least-once). A torn tail line (no newline yet) waits for the next run.
// A malformed line is skipped and counted without burning a sequence number.
// A file shorter than the offset is a rotation: the offset resets to zero,
// the sequence never does.
func (t *Tailer) RunOnce(ctx context.Context) {
	f, err := os.Open(t.logPath) // #nosec G304 -- operator-configured log path
	if err != nil {
		return // absent log = nothing to bridge this tick
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return
	}
	if info.Size() < t.cur.Offset {
		// Rotation/truncation: restart the offset, never the sequence.
		t.cur.Offset = 0
		_ = t.persist()
	}
	if _, err := f.Seek(t.cur.Offset, 0); err != nil {
		return
	}

	r := bufio.NewReader(f)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			// A torn tail (no newline) or EOF: wait for the writer.
			return
		}
		lineLen := int64(len(line))
		trimmed := strings.TrimSuffix(line, "\n")

		env, cerr := Convert([]byte(trimmed), t.cur.Sequence+1)
		if cerr != nil {
			// Poisoned line: skip and count, do not burn a sequence number,
			// do not wedge the bridge.
			t.skipped++
			t.cur.Offset += lineLen
			_ = t.persist()
			continue
		}
		if perr := t.pub.Publish(ctx, env); perr != nil {
			// Not delivered: keep the cursor; retry the SAME line with the
			// SAME sequence next run (at-least-once).
			return
		}
		t.cur.Sequence++
		t.cur.Offset += lineLen
		if err := t.persist(); err != nil {
			return
		}
	}
}

// persist writes the cursor durably (temp+rename).
func (t *Tailer) persist() error {
	raw, err := json.Marshal(t.cur)
	if err != nil {
		return err
	}
	dir := filepath.Dir(t.cursorPath)
	tmp, err := os.CreateTemp(dir, ".edgetail-cursor-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, t.cursorPath); err != nil {
		return fmt.Errorf("edgetail: persist cursor: %w", err)
	}
	return nil
}
