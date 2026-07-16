<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# ocu-audit

Central audit fan-in service for the OCU next/v1 fleet (component-07). It
terminates the per-source mTLS ingest face, host-attests each source, authors a
per-source tamper-evident hash chain, durably commits every event before
acknowledging, and signs one daily Merkle head.

The design and its invariants are canon: see
[`docs/architecture/components/07-audit-pipeline.md`](https://github.com/Wide-Moat/open-computer-use/blob/next/v1/docs/architecture/components/07-audit-pipeline.md),
[`ADR-0009`](https://github.com/Wide-Moat/open-computer-use/blob/next/v1/docs/architecture/adr/0009-audit-pipeline-pluggable-by-contract.md),
and the wire contract [`contracts/audit/audit-fanin.asyncapi.yaml`](contracts/audit/audit-fanin.asyncapi.yaml).

## What it guarantees

- **Host-attested source (INV-1).** The OCSF `source` is the verified mTLS peer
  identity, never a payload value. A publish body carrying a `source`,
  `prev_hash`, or `chain_hash` key is rejected at decode.
- **Channel binding (INV-2).** A peer publishes only to its authorized channel.
  The `session-sandbox` channel is host-authored by the control exec-driver peer
  (NFR-SEC-47); the guest never publishes.
- **Pipeline-authored chain (INV-3).** Each source has its own SHA-256 hash
  chain: `SHA-256(prev_hash || uint64-BE(sequence) || canonical-event-bytes)`.
  Any mutation, reorder, insertion, or deletion of a committed record breaks the
  chain.
- **Durable commit before ack (INV-4).** Every admitted event is fsynced to the
  append-only WAL before the source receives a 200. An fsync fault returns a
  non-200; the source must not treat the event as committed.
- **Daily Merkle head.** Leaves are the committed chain hashes in commit order.
  The head and RFC-6962 inclusion/consistency proofs use
  `github.com/transparency-dev/merkle` (Apache-2.0). The head-submission
  envelope is signed with a host-local Ed25519 key; the pipeline signs only the
  envelope, not the head.

## Independent verifier

`ocu-audit-verify` is a separate process that reads the raw WAL bytes,
recomputes every per-source chain from genesis, recomputes the head, verifies
the envelope signature against a pinned public key, and checks inclusion and
consistency proofs. It shares no in-memory state with the writer.

```
go build ./cmd/ocu-audit-verify
./ocu-audit-verify -wal audit.wal -head audit-head.json \
  -pubkey <hex-ed25519-pubkey> -sample 3 -consistency-size 4
```

A tamper of one WAL byte (record content or framing) makes it exit non-zero.

## Build and test

```
go build ./...
go test ./...
go test -race ./...
bash scripts/mutation-floor.sh   # armed mutation floor over internal/chain
```

## Trust boundary

The service is the sole custodian of the audit store, the Merkle accumulator,
and the envelope-signing key. It holds no upstream credential, no kill-switch
route, and no session-mutation path: every fan-in operation is `receive`-only.
On the minimal shelf the durable bus is the embedded WAL and the head is signed
with a host-local key; the full shelf swaps the sink and the signer per
ADR-0009, leaving the boundary properties unchanged.
