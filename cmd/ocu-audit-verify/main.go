// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Command ocu-audit-verify is the INDEPENDENT verifier: a separate process that
// reads the raw WAL bytes, recomputes every per-source hash chain from genesis,
// recomputes the daily Merkle head from the committed chain hashes, verifies the
// head-envelope Ed25519 signature against a pinned public key, and verifies an
// inclusion proof for a sampled record and a consistency proof against an
// earlier head. It shares no in-memory state with the writer; it trusts only
// the bytes on disk and the pinned key. A non-zero exit means the store failed
// verification (tamper, reorder, deletion, sequence regression, head mismatch,
// or bad signature).
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/Wide-Moat/ocu-audit/internal/merkletree"
	"github.com/Wide-Moat/ocu-audit/internal/signer"
	"github.com/Wide-Moat/ocu-audit/internal/store"
)

// version is stamped by the release build (-X main.version); "dev" identifies a
// non-release build in the -version output.
var version = "dev"

func main() {
	var (
		walPath     = flag.String("wal", "audit.wal", "append-only WAL path to verify")
		headPath    = flag.String("head", "audit-head.json", "signed daily-head submission envelope")
		pubHex      = flag.String("pubkey", "", "pinned Ed25519 public key (hex, 32 bytes)")
		sampleIndex = flag.Uint64("sample", 0, "record index to prove inclusion for")
		consistency = flag.Int64("consistency-size", -1, "earlier tree size to prove consistency against (-1 to skip)")
		showVersion = flag.Bool("version", false, "print the build version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	if *pubHex == "" {
		fatalf("ocu-audit-verify: -pubkey (pinned Ed25519 public key, hex) is required")
	}
	pinnedPub, err := hex.DecodeString(*pubHex)
	if err != nil {
		fatalf("ocu-audit-verify: decode pubkey: %v", err)
	}

	records, err := store.ReadRawRecords(*walPath)
	if err != nil {
		fatalf("ocu-audit-verify: read wal: %v", err)
	}

	headBytes, err := os.ReadFile(*headPath)
	if err != nil {
		fatalf("ocu-audit-verify: read head: %v", err)
	}
	sh, err := signer.UnmarshalSignedHead(headBytes)
	if err != nil {
		fatalf("ocu-audit-verify: parse head: %v", err)
	}

	res, err := store.VerifyStore(records, sh, pinnedPub, *sampleIndex)
	if err != nil {
		fatalf("ocu-audit-verify: FAIL: %v", err)
	}

	fmt.Printf("chains OK: %d records across sources %v\n", res.RecordCount, res.Sources)
	fmt.Printf("head OK: %s (tree_size=%d, date=%s)\n",
		hex.EncodeToString(res.Head), sh.Envelope.TreeSize, sh.Envelope.Date)
	fmt.Printf("envelope signature OK against pinned key %s\n", *pubHex)
	if res.RecordCount > 0 {
		fmt.Printf("inclusion proof OK for record %d\n", *sampleIndex)
	}

	// Optional consistency proof against an earlier head. Recompute the earlier
	// head from a prefix of the raw records so the proof is self-contained.
	if *consistency >= 0 {
		size1 := uint64(*consistency)
		if size1 > uint64(len(records)) {
			fatalf("ocu-audit-verify: consistency size %d > record count %d", size1, len(records))
		}
		prefix := records[:size1]
		root1, err := store.RecomputeHead(prefix)
		if err != nil {
			fatalf("ocu-audit-verify: recompute earlier head: %v", err)
		}
		acc := merkletree.New()
		for i, r := range records {
			if err := acc.AppendLeaf(r.ChainHash); err != nil {
				fatalf("ocu-audit-verify: rebuild leaf %d: %v", i, err)
			}
		}
		prf, err := acc.ConsistencyProof(size1)
		if err != nil {
			fatalf("ocu-audit-verify: build consistency proof: %v", err)
		}
		if err := merkletree.VerifyConsistency(
			size1, uint64(len(records)), root1, res.Head, prf); err != nil {
			fatalf("ocu-audit-verify: consistency proof FAIL: %v", err)
		}
		fmt.Printf("consistency proof OK: size %d -> %d\n", size1, len(records))
	}

	fmt.Println("VERIFY OK")
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
