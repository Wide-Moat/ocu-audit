<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# Wire surface

How a host-side source publishes to the ocu-audit fan-in, and how the daily head
is verified. The canonical contract is
[`contracts/audit/audit-fanin.asyncapi.yaml`](../contracts/audit/audit-fanin.asyncapi.yaml);
this page states the HTTP binding the service implements for the solo F10 shelf.

## Ingest (per-source, mTLS)

One route per channel address, POST only:

```
POST /v1alpha/audit/<channel-address>
```

`<channel-address>` is a contract channel address, e.g. `audit.ingest.control-plane`.
The connection is mutual TLS; the verified client-certificate common name is the
host-attested source. The request body is a JSON envelope:

```json
{
  "trace_id": "...",
  "session_id": "...",
  "actor_id": "...",
  "resource": "...",
  "action": "...",
  "outcome": "success",
  "sequence": 42,
  "payload": { "...": "an OCSF v1.x event class" }
}
```

The body carries no `source`, `prev_hash`, or `chain_hash`: the source is the
verified channel identity and the chain linkage is authored by the pipeline. A
body carrying any of those keys is rejected with 400.

| Response | Meaning |
|---|---|
| 200 | Durably committed (fsynced) and chained. This is the ack. |
| 400 | Malformed envelope, bounds violation, or a smuggled chain/source key. |
| 401 | No verified client certificate. |
| 403 | Peer not authorized for this channel (INV-2). |
| 409 | Sequence not strictly greater than the source's last committed sequence. |
| 503 | Durable commit could not be guaranteed (fsync fault). Not committed. |

A 200 is issued only after the write-ahead log fsync succeeds. Any non-200 means
the event is not committed; the source retries with the same sequence.

## Peer-to-channel authorization

The map is host-authored config, 1:1 by default: a peer whose certificate common
name equals a channel's source label may publish that channel. The
`session-sandbox` channel is the exception (NFR-SEC-47): the guest never
publishes; the control exec-driver peer host-authors sandbox events on the
guest's behalf.

## Daily head and verification

The head is signed with a host-local Ed25519 key and written as a submission
envelope (`audit-head.json`). Verify a store with the independent binary:

```
ocu-audit-verify -wal audit.wal -head audit-head.json \
  -pubkey <hex-pubkey> -sample <index> -consistency-size <earlier-size>
```

It recomputes every chain from genesis, recomputes the head, verifies the
envelope signature against the pinned public key, and checks an inclusion proof
for the sampled record plus a consistency proof against the earlier size. A
non-zero exit means the store failed verification.
