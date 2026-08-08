// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingest

import "testing"

// INV-2 acceptance anchor (component-07): "an integration test driving one
// source's credential against every OTHER channel." The keystone test proves
// the HTTP path for a single pair; this drives the full cross-product against
// PeerChannelAuthz directly, so no source credential can reach a channel it does
// not own and no owner is accidentally locked out of its own.
//
// The authorization is host-authored config keyed on the verified peer CN, so
// the matrix is the whole of INV-2's logic — the mTLS terminator only supplies
// the CN that indexes it.

const testExecDriverCN = "control-exec-driver"

// peerCNs are the verified client-cert CNs a real deployment presents: one per
// emitting source, plus the control exec-driver that host-authors the guest's
// channel (NFR-SEC-47).
func peerCNs() []string {
	cns := make([]string, 0, len(Channels)+1)
	cns = append(cns, testExecDriverCN)
	for _, ch := range Channels {
		cns = append(cns, ch.Source)
	}
	return cns
}

// ownedBy is the authoritative expectation the matrix is checked against,
// written out independently of DefaultAuthz so a bug in the builder cannot also
// corrupt the oracle. A peer owns exactly the channel whose source is its CN —
// EXCEPT session-sandbox, which no guest publishes and only the exec-driver may
// host-author.
func ownedBy(peerCN, address string) bool {
	source, ok := sourceForAddress(address)
	if !ok {
		return false
	}
	if source == "session-sandbox" {
		return peerCN == testExecDriverCN
	}
	return peerCN == source
}

// TestINV2FullCrossProduct is the acceptance anchor. Every (peer, channel) pair
// is checked, so a credential authorized for a channel it must not reach reds
// here, and so does an owner denied its own channel.
func TestINV2FullCrossProduct(t *testing.T) {
	authz := DefaultAuthz(testExecDriverCN)

	var checked int
	for _, peer := range peerCNs() {
		for _, ch := range Channels {
			want := ownedBy(peer, ch.Address)
			got := authz.Authorized(peer, ch.Address)
			checked++
			if got != want {
				verb := "was DENIED"
				if got {
					verb = "was ALLOWED"
				}
				t.Errorf("peer %q -> %q %s, want authorized=%v — a source must publish "+
					"only to its own channel (INV-2)", peer, ch.Address, verb, want)
			}
		}
	}

	// The matrix must actually be a matrix: with 7 peers and 6 channels a
	// vacuous loop (empty Channels, say) would pass every assertion while
	// proving nothing.
	if want := len(peerCNs()) * len(Channels); checked != want {
		t.Fatalf("checked %d pairs, want %d — the cross-product did not run in full", checked, want)
	}
}

// TestINV2SessionSandboxIsHostAuthoredOnly pins the NFR-SEC-47 exception apart
// from the 1:1 rule, because it is the one place the rule bends: a peer whose CN
// is literally "session-sandbox" (a guest asserting its own source) must be
// refused, and only the exec-driver admitted.
func TestINV2SessionSandboxIsHostAuthoredOnly(t *testing.T) {
	authz := DefaultAuthz(testExecDriverCN)
	const addr = "audit.ingest.session-sandbox"

	if authz.Authorized("session-sandbox", addr) {
		t.Error("a peer presenting the session-sandbox CN was authorized to publish " +
			"the guest's own channel; the guest never publishes it (NFR-SEC-47)")
	}
	if !authz.Authorized(testExecDriverCN, addr) {
		t.Error("the control exec-driver was denied the session-sandbox channel it " +
			"host-authors on the guest's behalf")
	}
	// The exec-driver does NOT thereby gain every channel — only the one it
	// host-authors plus (if its CN coincided with a source) its own.
	if authz.Authorized(testExecDriverCN, "audit.ingest.mcp-gateway") {
		t.Error("the exec-driver was authorized for the mcp-gateway channel; the " +
			"host-authoring exception is scoped to session-sandbox alone")
	}
}

// TestINV2UnknownPeerAndChannelFailClosed pins the default direction: a CN or
// address absent from the host-authored map is denied, never admitted.
func TestINV2UnknownPeerAndChannelFailClosed(t *testing.T) {
	authz := DefaultAuthz(testExecDriverCN)

	if authz.Authorized("stranger", "audit.ingest.control-plane") {
		t.Error("an unrecognised peer CN was authorized; an unknown peer must fail closed")
	}
	if authz.Authorized("control-plane", "audit.ingest.unknown-channel") {
		t.Error("a known peer was authorized for an unknown channel address")
	}
	if authz.Authorized("", "audit.ingest.control-plane") {
		t.Error("an empty peer CN was authorized")
	}
}
