// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingest

import (
	"testing"
)

// NFR-SEC-56 / component-07 INV-6: per-source ingest fairness at the fan-in.
// A source exceeding its provisioned share is RATE-SHAPED (not dropped),
// COUNTED, and emits a SATURATION event; co-tenant sources keep full headroom
// and the committed chain stays unbroken. Fairness keys on the host-attested
// source label (the channel binding), never a payload field.
//
// The limiter is a per-source token bucket over an injected clock so the tests
// are deterministic. "Rate-shape not drop" is modelled as: admission is PACED —
// a source with no token available is told to wait (retryable), never that its
// event is discarded. Nothing is admitted out of order, so the chain never
// breaks whether the source waits or gives up.

// fairClock is a scripted monotonic clock in milliseconds.
type fairClock struct{ now int64 }

func (c *fairClock) NowMillis() int64 { return c.now }
func (c *fairClock) advance(ms int64) { c.now += ms }

// TestOneSourceFloodIsCappedCoTenantKeepsHeadroom is the keystone. One source
// floods well past its share; its admitted count is capped at the bucket
// capacity while a co-tenant source, publishing within its share, is admitted
// every time. A shared or mis-keyed bucket would let the flood starve the
// co-tenant, reding this.
func TestOneSourceFloodIsCappedCoTenantKeepsHeadroom(t *testing.T) {
	clk := &fairClock{now: 0}
	// share: 5 tokens burst, refilling 1 token per 100ms, per source.
	lim := newLimiter(FairnessShare{Burst: 5, RefillEveryMillis: 100}, clk)

	// The flood source hammers 20 times with no clock advance: only the burst
	// capacity of 5 may pass; the rest are shaped (told to wait).
	floodAdmitted := 0
	for i := 0; i < 20; i++ {
		if lim.admit("object-store") {
			floodAdmitted++
		}
	}
	if floodAdmitted != 5 {
		t.Fatalf("flood source admitted %d, want the burst cap 5 — the over-share was "+
			"not rate-shaped", floodAdmitted)
	}

	// A co-tenant source, having spent none of its own bucket, keeps full
	// headroom: its first 5 all pass despite the flood next door.
	coTenantAdmitted := 0
	for i := 0; i < 5; i++ {
		if lim.admit("control-plane") {
			coTenantAdmitted++
		}
	}
	if coTenantAdmitted != 5 {
		t.Fatalf("co-tenant admitted %d of 5 within its share; the flood source "+
			"starved a co-tenant — buckets are not per-source", coTenantAdmitted)
	}
}

// TestOverShareIsCountedNotDropped pins the counter half: every shaped event is
// counted per source, and the count is exactly the over-share (attempts beyond
// the burst), never the whole attempt volume.
func TestOverShareIsCountedNotDropped(t *testing.T) {
	clk := &fairClock{now: 0}
	lim := newLimiter(FairnessShare{Burst: 3, RefillEveryMillis: 100}, clk)

	for i := 0; i < 10; i++ {
		lim.admit("web-ui")
	}
	// 3 admitted, 7 shaped.
	if got := lim.OverShare("web-ui"); got != 7 {
		t.Fatalf("over-share count = %d, want 7 (10 attempts - 3 burst)", got)
	}
	// A source that never over-ran has a zero count — the counter discriminates.
	if got := lim.OverShare("control-plane"); got != 0 {
		t.Fatalf("a source that stayed within share has over-share %d, want 0", got)
	}
}

// TestRefillRestoresShareOverTime keeps the shaping temporary, not a permanent
// ban: after the refill interval elapses the source regains a token. A bucket
// that never refills would shape a well-behaved source forever.
func TestRefillRestoresShareOverTime(t *testing.T) {
	clk := &fairClock{now: 0}
	lim := newLimiter(FairnessShare{Burst: 1, RefillEveryMillis: 100}, clk)

	if !lim.admit("egress-edge") {
		t.Fatal("first event should pass on a fresh bucket")
	}
	if lim.admit("egress-edge") {
		t.Fatal("second immediate event should be shaped (burst 1, no refill yet)")
	}
	clk.advance(100)
	if !lim.admit("egress-edge") {
		t.Fatal("after one refill interval the source should regain a token; the " +
			"bucket never refilled and the shaping is a permanent ban")
	}
}

// TestSaturationFiresOnFirstOverShareOncePerEpisode pins the saturation signal:
// the limiter reports a saturation-onset the first time a source crosses into
// over-share, and does not re-fire on every subsequent shaped event within the
// same saturated episode (which would flood the self-emit channel it is
// warning about).
func TestSaturationFiresOnFirstOverShareOncePerEpisode(t *testing.T) {
	clk := &fairClock{now: 0}
	lim := newLimiter(FairnessShare{Burst: 2, RefillEveryMillis: 100}, clk)

	// Consume the burst (2 tokens): these admit, no saturation yet.
	for i := 0; i < 2; i++ {
		if !lim.admit("mcp-gateway") {
			t.Fatalf("burst admit %d should pass on a fresh bucket", i)
		}
	}
	fires := 0
	for i := 0; i < 5; i++ {
		if !lim.admit("mcp-gateway") {
			if lim.saturationOnset("mcp-gateway") {
				fires++
			}
		}
	}
	if fires != 1 {
		t.Fatalf("saturation onset fired %d times in one episode, want exactly 1 — "+
			"the self-emit warning either never fires or floods", fires)
	}
}
