// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingest

import "sync"

// Per-source ingest fairness at the fan-in boundary (NFR-SEC-56, component-07
// INV-6). A source exceeding its provisioned share is rate-shaped — not
// dropped — counted, and its first over-share in an episode reports a
// saturation onset so the pipeline can self-emit a saturation event on its own
// channel. Buckets are per host-attested source, so one source's over-share
// never consumes another's headroom.
//
// The share is a token bucket: Burst tokens available at once, refilling one
// token every RefillEveryMillis. Fairness keys on the CHANNEL-bound source
// label (server.go binds it from the verified peer, never the payload), so a
// guest-settable field can neither raise its own share nor spend a co-tenant's.

// clock reads a monotonic millisecond time. store.SystemClock satisfies it in
// production; a scripted clock drives the tests. It is a local interface so the
// leaf fairness logic carries no store dependency.
type clock interface {
	NowMillis() int64
}

// FairnessShare is the per-source provisioned ingest share.
type FairnessShare struct {
	// Burst is the token-bucket capacity: the most a source may admit back to
	// back before refill governs its rate. Must be > 0.
	Burst int
	// RefillEveryMillis is the interval that restores one token. Must be > 0;
	// a source regains its full share over Burst*RefillEveryMillis of quiet.
	RefillEveryMillis int64
}

// bucket is one source's live token state.
type bucket struct {
	tokens        int
	lastRefill    int64 // clock time of the last refill accounting
	overShare     int64 // count of shaped (over-share) events for this source
	saturated     bool  // currently inside a saturated episode (shaped, no admit since)
	onsetReported bool  // saturation onset already reported for this episode
}

// limiter holds the per-source buckets behind one lock. The map is small
// (bounded by the fixed channel set) and every operation is O(1), so a single
// mutex is not a fan-in bottleneck.
type limiter struct {
	share FairnessShare
	clk   clock

	mu      sync.Mutex
	buckets map[string]*bucket
}

// newLimiter builds a fairness limiter over share and clk. A non-positive Burst
// or RefillEveryMillis is a programming error the caller normalises before
// construction; the limiter clamps them to 1 so a mis-set share fails toward
// admitting rather than a divide-by-zero or a permanent block.
func newLimiter(share FairnessShare, clk clock) *limiter {
	if share.Burst < 1 {
		share.Burst = 1
	}
	if share.RefillEveryMillis < 1 {
		share.RefillEveryMillis = 1
	}
	return &limiter{
		share:   share,
		clk:     clk,
		buckets: make(map[string]*bucket),
	}
}

// bucketFor returns the source's bucket, creating it full on first sight so a
// source starts with its whole burst.
func (l *limiter) bucketFor(source string) *bucket {
	b, ok := l.buckets[source]
	if !ok {
		b = &bucket{tokens: l.share.Burst, lastRefill: l.clk.NowMillis()}
		l.buckets[source] = b
	}
	return b
}

// refill credits whole refill intervals elapsed since lastRefill, capped at
// Burst. It advances lastRefill only by the intervals actually consumed so
// sub-interval time is not lost to rounding.
func (l *limiter) refill(b *bucket, now int64) {
	if b.tokens >= l.share.Burst {
		b.lastRefill = now
		return
	}
	elapsed := now - b.lastRefill
	if elapsed < l.share.RefillEveryMillis {
		return
	}
	gained := int(elapsed / l.share.RefillEveryMillis)
	b.tokens += gained
	if b.tokens > l.share.Burst {
		b.tokens = l.share.Burst
	}
	b.lastRefill += int64(gained) * l.share.RefillEveryMillis
}

// admit reports whether the source may admit one event now. A token is spent on
// admit. When no token is available the event is SHAPED: admit returns false,
// the over-share counter increments, and the source enters (or stays in) a
// saturated episode. Shaping never discards — the caller paces/retries; nothing
// is admitted out of order, so the committed chain stays unbroken.
func (l *limiter) admit(source string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.clk.NowMillis()
	b := l.bucketFor(source)
	l.refill(b, now)

	if b.tokens > 0 {
		b.tokens--
		// An admitted event closes any saturated episode: a later relapse is a
		// new episode that reports its own onset.
		b.saturated = false
		b.onsetReported = false
		return true
	}
	b.overShare++
	b.saturated = true
	return false
}

// saturationOnset reports true exactly once per saturated episode: the first
// shaped event after the source crossed into over-share. Subsequent shaped
// events in the same episode return false so the self-emit saturation warning
// does not itself flood the channel it is warning about. An admitted event
// closes the episode (admit clears the flags), so a later relapse fires again.
func (l *limiter) saturationOnset(source string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[source]
	if !ok || !b.saturated || b.onsetReported {
		return false
	}
	b.onsetReported = true
	return true
}

// OverShare returns the count of shaped events for the source, for the
// operator-visible fairness metric. Zero for a source that stayed within share.
func (l *limiter) OverShare(source string) int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[source]
	if !ok {
		return 0
	}
	return b.overShare
}
