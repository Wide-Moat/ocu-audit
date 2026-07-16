<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# Changelog

All notable changes to ocu-audit are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Central audit fan-in service (component-07, increment 1):
  - mTLS HTTP ingest face, one route per contract channel address, with an
    explicit peer-to-channel authorization map (1:1 default; the session-sandbox
    channel is host-authored by the control exec-driver peer per NFR-SEC-47).
  - Per-source monotonic sequence enforcement with `(source, sequence)` replay
    dedupe.
  - Pipeline-authored per-source SHA-256 hash chain
    (`prev_hash || uint64-BE(sequence) || canonical-event-bytes`); chain linkage
    is never read from a publish payload.
  - Daily Merkle head over committed chain hashes with RFC-6962 inclusion and
    consistency proofs (`github.com/transparency-dev/merkle`, Apache-2.0).
  - Ed25519 head-envelope signer (host-local key, ADR-0009 solo custody).
  - Embedded append-only WAL as the solo-shelf durable bus; fsync-then-ack
    (INV-4) with a writeSyncer fault-injection seam.
  - Independent verifier binary `cmd/ocu-audit-verify` that recomputes chains,
    the head, and proofs from the raw store and verifies the envelope signature.
- CI scaffold: go (gofmt / vet / staticcheck / golangci / test / race /
  govulncheck), security (gitleaks / trufflehog / semgrep / trivy fs CRITICAL+
  HIGH / lexicon), and an armed nightly mutation floor over the hash-chain guard
  with a per-PR freshness gate.
