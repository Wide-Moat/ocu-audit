// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package ingest is the fan-in face: an mTLS HTTP server with one route per
// audit channel address, an explicit peer -> channel authorization map, and the
// host-attested source binding. The verified mTLS peer identity is the OCSF
// source; a peer publishing to a channel it is not authorized for is rejected
// (INV-2), nothing is admitted, and the chains stay unbroken.
package ingest

// Channel is one audit fan-in channel from the AsyncAPI contract. The route is
// the channel address; the source is the OCSF source label bound to any event
// admitted on it.
type Channel struct {
	// Address is the contract channel address, used as the HTTP route path
	// suffix (e.g. audit.ingest.control-plane).
	Address string
	// Source is the host-attested OCSF source label for events on this channel.
	Source string
}

// Channels enumerates the fan-in channels from
// contracts/audit/audit-fanin.asyncapi.yaml. The self-emit channel
// (audit.ingest.audit-pipeline) is internally originated and has no wire peer,
// so it is not routable here.
var Channels = []Channel{
	{Address: "audit.ingest.mcp-gateway", Source: "mcp-gateway"},
	{Address: "audit.ingest.control-plane", Source: "control-plane"},
	{Address: "audit.ingest.object-store", Source: "object-store"},
	{Address: "audit.ingest.web-ui", Source: "web-ui"},
	{Address: "audit.ingest.session-sandbox", Source: "session-sandbox"},
	{Address: "audit.ingest.egress-edge", Source: "egress-edge"},
}

// PeerChannelAuthz maps a verified peer identity (mTLS certificate common name)
// to the set of channel addresses that peer may publish to. Default is 1:1: a
// peer publishes only to its own channel (INV-2). sessionSandboxAudit is a
// special case per NFR-SEC-47: the guest does not publish; the channel is owned
// by the control exec-driver peer, which host-authors sandbox events on the
// guest's behalf. This mapping is host-authored config, never derived from the
// payload.
type PeerChannelAuthz struct {
	// allow maps peer CN -> set of channel addresses.
	allow map[string]map[string]struct{}
}

// DefaultAuthz builds the 1:1 map plus the NFR-SEC-47 exception: the control
// exec-driver peer (peerCN == controlExecDriverCN) is additionally authorized
// to publish the session-sandbox channel, which the guest itself may never
// publish. Every other peer is authorized only for the channel whose source
// equals its own CN.
func DefaultAuthz(controlExecDriverCN string) *PeerChannelAuthz {
	allow := make(map[string]map[string]struct{})
	for _, ch := range Channels {
		// 1:1: the peer whose CN matches the channel source owns that channel.
		if ch.Source == "session-sandbox" {
			// The guest never publishes its own channel (NFR-SEC-47); it is
			// host-authored by the control exec-driver peer below. Do NOT grant
			// a "session-sandbox" CN peer this channel.
			continue
		}
		addPeerChannel(allow, ch.Source, ch.Address)
	}
	// NFR-SEC-47: control exec-driver host-authors sandbox events.
	addPeerChannel(allow, controlExecDriverCN, "audit.ingest.session-sandbox")
	return &PeerChannelAuthz{allow: allow}
}

func addPeerChannel(allow map[string]map[string]struct{}, peerCN, address string) {
	set, ok := allow[peerCN]
	if !ok {
		set = make(map[string]struct{})
		allow[peerCN] = set
	}
	set[address] = struct{}{}
}

// Authorized reports whether the verified peer CN may publish to the channel
// address. A peer or channel absent from the map is denied (fail-closed).
func (a *PeerChannelAuthz) Authorized(peerCN, address string) bool {
	set, ok := a.allow[peerCN]
	if !ok {
		return false
	}
	_, ok = set[address]
	return ok
}

// sourceForAddress returns the host-attested source label for a channel
// address, or false if the address is not a known channel.
func sourceForAddress(address string) (string, bool) {
	for _, ch := range Channels {
		if ch.Address == address {
			return ch.Source, true
		}
	}
	return "", false
}
