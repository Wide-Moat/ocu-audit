// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingest

import (
	"net/http"
	"testing"
)

// The fan-in path applies per-source fairness after peer authorization and
// before admission (component-07: "Per-source ingest fairness is applied before
// admission"). These drive the real mTLS server to prove the wiring: a flood on
// one channel is shaped with a retryable status while a co-tenant keeps
// headroom, the committed chain stays unbroken, and the pipeline self-emits a
// saturation record on its own channel — never inventing an OCSF class for the
// still-TBD saturation payload.

// newFairRig is the keystone rig with fairness wired at a small share so a short
// burst saturates deterministically. The clock is frozen (zeroStoreClock reads
// 0 and never advances), so no refill masks the shaping within the test.
func newFairRig(t *testing.T, burst int) *keystoneRig {
	t.Helper()
	r := newKeystoneRigBare(t)
	share := FairnessShare{Burst: burst, RefillEveryMillis: 100}
	handler := NewServerWithFairness(r.store, DefaultAuthz("control-plane"), MTLSPeerVerifier{}, share, frozenClock{}).Handler()
	r.startTLS(t, handler)
	return r
}

// frozenClock never advances: every fairness decision in a test sees the same
// instant, so the burst is the whole admissible budget.
type frozenClock struct{}

func (frozenClock) NowMillis() int64 { return 0 }

// TestFairnessShapesFloodOverHTTPCoTenantKeepsHeadroom is the wiring keystone.
// The object-store channel floods; after its burst it receives a retryable
// 429 (shaped, not a 4xx-permanent reject and not a silent drop). The
// control-plane co-tenant, within its own share, still gets 200 on every
// publish. Every 200 is a durably committed record, so the chain is unbroken.
func TestFairnessShapesFloodOverHTTPCoTenantKeepsHeadroom(t *testing.T) {
	r := newFairRig(t, 3)
	flood := r.clientFor(t, "object-store")
	coTenant := r.clientFor(t, "control-plane")

	admitted, shaped := 0, 0
	for i := uint64(1); i <= 10; i++ {
		resp := r.publish(t, flood, "audit.ingest.object-store", event(i, "object-store"))
		switch resp.StatusCode {
		case http.StatusOK:
			admitted++
		case http.StatusTooManyRequests:
			shaped++
		default:
			t.Fatalf("flood publish %d got status %d, want 200 or 429", i, resp.StatusCode)
		}
	}
	if admitted != 3 {
		t.Fatalf("flood admitted %d, want the burst 3 — fairness did not shape the over-share", admitted)
	}
	if shaped != 7 {
		t.Fatalf("flood shaped %d, want 7 retryable 429s — the over-share was dropped or admitted", shaped)
	}

	// The co-tenant keeps full headroom: its whole burst is admitted despite the
	// flood on the neighbouring channel.
	for i := uint64(1); i <= 3; i++ {
		resp := r.publish(t, coTenant, "audit.ingest.control-plane", event(i, "control-plane"))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("co-tenant publish %d got %d, want 200 — the flood starved a co-tenant", i, resp.StatusCode)
		}
	}
}

// TestSaturationSelfEmittedOnPipelineChannel pins the self-emit half: once a
// source is shaped, a saturation record appears on the internally-originated
// audit-pipeline source, naming the saturated source. The saturation payload
// carries no OCSF class assertion (Open-Q #5): the test checks the record
// exists and attributes the saturated source, not a class_uid.
func TestSaturationSelfEmittedOnPipelineChannel(t *testing.T) {
	r := newFairRig(t, 2)
	flood := r.clientFor(t, "web-ui")

	for i := uint64(1); i <= 6; i++ {
		r.publish(t, flood, "audit.ingest.web-ui", event(i, "web-ui"))
	}

	var sawSaturation bool
	for _, rec := range r.store.Records() {
		if rec.Source == selfEmitSource && rec.Action == saturationAction {
			sawSaturation = true
			if want := "web-ui"; rec.Resource != want {
				t.Fatalf("saturation record names resource %q, want the saturated source %q", rec.Resource, want)
			}
		}
	}
	if !sawSaturation {
		t.Fatal("no saturation record self-emitted on the audit-pipeline channel after a flood; " +
			"the over-share was shaped silently, defeating NFR-SEC-56's saturation signal")
	}
}
