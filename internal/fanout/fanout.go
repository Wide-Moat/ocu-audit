// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package fanout is the decoupled SIEM-side bridge (component-07 P7-D1,
// NFR-REL-12): committed records flow store -> sink OFF the admission path,
// resumed across restarts by a durable cursor. The transport is deliberately
// unpinned — Sink is the seam a customer collector fills; FileSink is the
// solo-shelf reference. Delivery is at-least-once: the cursor advances only
// after a successful emit, so a mid-drain failure retries rather than skips.
// A cursor lagging past the rotation boundary is a PERMANENT sink gap (the
// cold tier still holds the records): counted, evidenced once, and skipped —
// rotation is never hostage to sink health.
package fanout

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/Wide-Moat/ocu-audit/internal/ocsf"
	"github.com/Wide-Moat/ocu-audit/internal/store"
)

// ActionFanoutGap labels the self-emitted evidence for records the sink
// permanently missed (rotated before delivery). The payload schema stays
// minimal (no OCSF class exists for it; component-07 Open Question).
const ActionFanoutGap = "fanout.gap"

// Sink is the delivery seam. An error means NOT delivered: the pump keeps
// the cursor and retries on a later run.
type Sink interface {
	Emit(rec *ocsf.Record) error
}

// cursorFile is the durable position: the next GLOBAL index to deliver.
type cursorFile struct {
	Next uint64 `json:"next"`
}

// Pump moves committed records to the sink, one RunOnce per tick, single
// goroutine. It is not safe for concurrent RunOnce calls.
type Pump struct {
	st         *store.Store
	sink       Sink
	cursorPath string
	// emit self-emits evidence (the ingest server's SelfEmit in production);
	// nil drops it (tests that don't assert evidence).
	emit func(action, resource string, payload map[string]any)

	mu       sync.Mutex
	next     uint64
	gapTotal uint64
}

// NewPump loads the cursor (absent = genesis) and returns the pump.
func NewPump(st *store.Store, sink Sink, cursorPath string, emit func(action, resource string, payload map[string]any)) *Pump {
	p := &Pump{st: st, sink: sink, cursorPath: cursorPath, emit: emit}
	raw, err := os.ReadFile(cursorPath) // #nosec G304 -- daemon-owned cursor path
	if err == nil {
		var c cursorFile
		if json.Unmarshal(raw, &c) == nil {
			p.next = c.Next
		}
	}
	return p
}

// Lag returns the committed-but-undelivered record count.
func (p *Pump) Lag() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	total := p.st.GlobalCount()
	if p.next >= total {
		return 0
	}
	return total - p.next
}

// GapTotal returns the records permanently missed at the sink (rotated
// before delivery).
func (p *Pump) GapTotal() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.gapTotal
}

// RunOnce delivers everything deliverable: skip-and-evidence any rotated
// gap, then emit hot records in commit order, advancing the durable cursor
// after each success. A sink error stops the run; the failed record retries
// next run.
func (p *Pump) RunOnce() {
	p.mu.Lock()
	defer p.mu.Unlock()

	offset := p.st.GlobalOffset()
	if p.next < offset {
		gap := offset - p.next
		p.gapTotal += gap
		p.next = offset
		_ = p.persistCursor()
		// One evidence record per gap EVENT: this block runs only when a
		// rotation passes the cursor, so each firing is a distinct loss and a
		// suppression flag would silently eat the evidence of a second gap.
		if p.emit != nil {
			p.emit(ActionFanoutGap, "fanout-cursor", map[string]any{
				"missed_records": gap,
				"cursor":         p.next,
				"note":           "rotated before delivery; the cold tier holds the records, the sink does not",
			})
		}
	}

	recs := p.st.RecordsFrom(p.next)
	for _, rec := range recs {
		if err := p.sink.Emit(rec); err != nil {
			return // cursor stays; retry next run (at-least-once)
		}
		p.next++
		if err := p.persistCursor(); err != nil {
			return
		}
	}
}

// persistCursor writes the cursor durably (temp+rename), so a crash between
// deliveries re-delivers at most the in-flight record.
func (p *Pump) persistCursor() error {
	raw, err := json.Marshal(cursorFile{Next: p.next})
	if err != nil {
		return err
	}
	dir := filepath.Dir(p.cursorPath)
	tmp, err := os.CreateTemp(dir, ".fanout-cursor-*")
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
	return os.Rename(name, p.cursorPath)
}

// FileSink is the solo-shelf reference sink: one JSON line per record,
// appended, not fsynced — the authoritative record is the hash-chained WAL;
// this file is a collector-consumable tail (the ADR-0009 file-system-sink
// default).
type FileSink struct {
	mu sync.Mutex
	f  *os.File
}

// NewFileSink opens (or creates) the append-only sink file.
func NewFileSink(path string) (*FileSink, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 -- operator-configured sink path
	if err != nil {
		return nil, fmt.Errorf("fanout: open sink: %w", err)
	}
	return &FileSink{f: f}, nil
}

// Emit appends one JSON line.
func (s *FileSink) Emit(rec *ocsf.Record) error {
	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("fanout: encode record: %w", err)
	}
	line = append(line, '\n')
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.f.Write(line); err != nil {
		return fmt.Errorf("fanout: write sink: %w", err)
	}
	return nil
}

// Close releases the sink file.
func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Close()
}
