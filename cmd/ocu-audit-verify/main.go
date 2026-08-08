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
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Wide-Moat/ocu-audit/internal/merkletree"
	"github.com/Wide-Moat/ocu-audit/internal/ocsf"
	"github.com/Wide-Moat/ocu-audit/internal/retention"
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
		coldDir     = flag.String("cold-dir", "", "cold-tier directory (ADR-0045); when set, verification spans the cold+hot union from genesis")
		cpPath      = flag.String("checkpoint", "", "signed retention checkpoint to audit (signature, floor, inventory vs the cold directory)")
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

	// With -cold-dir the verification spans the WHOLE horizon: cold segments
	// in index order, then the hot union — the genesis-anchored perimeter the
	// daemon's hot-only boot deliberately does not carry (ADR-0045).
	// Without it: the hot union alone (a pre-rotation deployment).
	var records []*ocsf.Record
	if *coldDir != "" {
		records, err = store.ReadUnion(*coldDir, *walPath)
	} else {
		records, err = store.ReadHotRecords(*walPath)
	}
	if err != nil {
		fatalf("ocu-audit-verify: read wal: %v", err)
	}

	// Checkpoint audit: signature under the pinned key, the NFR-COMP-01
	// floor, and every rotated inventory row's digest against the actual cold
	// segment bytes — the retention declaration must match the directory it
	// describes.
	if *cpPath != "" {
		cp, err := retention.AuditCheckpoint(*cpPath, pinnedPub)
		if err != nil {
			fatalf("ocu-audit-verify: checkpoint: %v", err)
		}
		if *coldDir == "" {
			fatalf("ocu-audit-verify: -checkpoint requires -cold-dir (the inventory audits the cold directory)")
		}
		for _, seg := range cp.Segments {
			if seg.RotatedAtMillis == 0 {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(*coldDir, seg.Name)) // #nosec G304 -- operator-supplied dir
			if err != nil {
				fatalf("ocu-audit-verify: checkpoint names rotated segment %s but the cold directory lacks it: %v", seg.Name, err)
			}
			sum := sha256.Sum256(raw)
			if !bytes.Equal(sum[:], seg.SHA256) {
				fatalf("ocu-audit-verify: cold segment %s digest %x does not match the signed inventory %x", seg.Name, sum[:8], seg.SHA256[:8])
			}
			recs, err := store.ReadRawRecords(filepath.Join(*coldDir, seg.Name))
			if err != nil || uint64(len(recs)) != seg.RecordCount {
				fatalf("ocu-audit-verify: cold segment %s carries %d records, inventory says %d (err=%v)", seg.Name, len(recs), seg.RecordCount, err)
			}
		}
		fmt.Printf("checkpoint ok: floor %d y, %d segments inventoried\n", cp.Policy.FloorYears, len(cp.Segments))
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
