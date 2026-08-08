// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package retention

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-audit/internal/signer"
)

// The signed retention checkpoint (ADR-0045) anchors hot-only boot: per-source
// chain tips, Merkle tree size and frontier at the last rotation, plus the
// full segment inventory and the declared policy. Load refuses a bad
// signature, a floor below the NFR-COMP-01 minimum, and a policy shrink —
// each with its OWN diagnostic, because a refusal a neighboring check repeats
// is unverifiable.

func testPolicy(t *testing.T, floorYears int) Policy {
	t.Helper()
	p, err := NewPolicy(floorYears, 2160*time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func testCheckpoint(t *testing.T, floorYears int) Checkpoint {
	t.Helper()
	return Checkpoint{
		Policy: testPolicy(t, floorYears),
		Segments: []SegmentEntry{
			{
				Name: "audit-000001.wal", SHA256: bytes.Repeat([]byte{0xAA}, 32),
				RecordCount: 3, FirstIngestMillis: 1000, LastIngestMillis: 3000,
				FirstGlobalIndex: 0, LastGlobalIndex: 2,
				SealedAtMillis: 4000, RotatedAtMillis: 5000,
				SealTips:     map[string]ChainTip{"control-plane": {Hash: bytes.Repeat([]byte{0x05}, 32), Seq: 2}},
				SealTreeSize: 3,
				SealFrontier: [][]byte{bytes.Repeat([]byte{0x06}, 32)},
			},
			{
				Name: "audit-000002.wal", SHA256: bytes.Repeat([]byte{0xBB}, 32),
				RecordCount: 2, FirstIngestMillis: 3500, LastIngestMillis: 4200,
				FirstGlobalIndex: 3, LastGlobalIndex: 4,
				SealedAtMillis: 5000, RotatedAtMillis: 0, // still hot
			},
		},
		ChainTips: map[string]ChainTip{
			"control-plane": {Hash: bytes.Repeat([]byte{0x01}, 32), Seq: 12},
			"object-store":  {Hash: bytes.Repeat([]byte{0x02}, 32), Seq: 7},
		},
		TreeSize: 3,
		Frontier: [][]byte{bytes.Repeat([]byte{0x03}, 32), bytes.Repeat([]byte{0x04}, 32)},
	}
}

func TestCheckpointRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "retention-checkpoint.json")
	sgn, err := signer.Generate()
	if err != nil {
		t.Fatal(err)
	}
	cp := testCheckpoint(t, 7)

	if err := WriteCheckpoint(path, cp, sgn); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := LoadCheckpoint(path, sgn.PublicKey(), testPolicy(t, 7))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.TreeSize != cp.TreeSize || len(got.Segments) != 2 ||
		got.Segments[0].Name != "audit-000001.wal" ||
		!bytes.Equal(got.ChainTips["control-plane"].Hash, cp.ChainTips["control-plane"].Hash) ||
		got.ChainTips["control-plane"].Seq != 12 ||
		len(got.Frontier) != 2 {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

// TestLoadRefusesTamperedCheckpoint uses a SEMANTICALLY NEUTRAL tamper — a
// rotatedAt timestamp bump that no floor/shrink/inventory check would refuse —
// re-marshaled without re-signing, so ONLY the signature check can catch it.
func TestLoadRefusesTamperedCheckpoint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "retention-checkpoint.json")
	sgn, err := signer.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteCheckpoint(path, testCheckpoint(t, 7), sgn); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var sc SignedCheckpoint
	if err := json.Unmarshal(raw, &sc); err != nil {
		t.Fatal(err)
	}
	sc.Checkpoint.Segments[0].RotatedAtMillis = 5001 // neutral: passes every semantic check
	tampered, err := json.Marshal(sc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = LoadCheckpoint(path, sgn.PublicKey(), testPolicy(t, 7))
	if err == nil {
		t.Fatal("a tampered checkpoint loaded; the signature does not bind the content")
	}
	if !strings.Contains(err.Error(), "signature") {
		t.Fatalf("tamper refusal diagnostic = %v, want the SIGNATURE diagnostic — "+
			"a semantic check is masking the signature check", err)
	}
}

// TestLoadRefusesFloorBelowMinimumEvenSigned hand-builds a VALIDLY SIGNED
// checkpoint whose floor is 6 — bypassing NewPolicy's validation, which a
// writer-side check would otherwise repeat — so only Load's own floor check
// can refuse it. The configured policy passes floor 7 > 6 to the shrink check,
// so the shrink check cannot mask it either.
func TestLoadRefusesFloorBelowMinimumEvenSigned(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "retention-checkpoint.json")
	sgn, err := signer.Generate()
	if err != nil {
		t.Fatal(err)
	}
	cp := testCheckpoint(t, 7)
	cp.Policy.FloorYears = 6 // forged directly; NewPolicy would refuse this
	sc := SignedCheckpoint{
		Checkpoint: cp,
		Signature:  sgn.SignMessage(cp.SignBytes()),
		PublicKey:  sgn.PublicKey(),
	}
	raw, err := json.Marshal(sc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = LoadCheckpoint(path, sgn.PublicKey(), testPolicy(t, 7))
	if err == nil {
		t.Fatal("a validly signed checkpoint with floor 6 loaded; the NFR-COMP-01 " +
			"minimum is not enforced at Load")
	}
	if !strings.Contains(err.Error(), "floor") || !strings.Contains(err.Error(), "6") {
		t.Fatalf("floor refusal diagnostic = %v, want the floor-specific message naming 6", err)
	}
}

// TestLoadRefusesShrink: checkpoint pinned at floor 10, configuration asks for
// 8. Both are valid policies and the signature is genuine, so only the shrink
// comparison can refuse — and its diagnostic must say shrink.
func TestLoadRefusesShrink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "retention-checkpoint.json")
	sgn, err := signer.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteCheckpoint(path, testCheckpoint(t, 10), sgn); err != nil {
		t.Fatal(err)
	}
	_, err = LoadCheckpoint(path, sgn.PublicKey(), testPolicy(t, 8))
	if err == nil {
		t.Fatal("a floor shrink from pinned 10 y to configured 8 y loaded; " +
			"retention shrink must refuse boot (ADR-0045)")
	}
	if !strings.Contains(err.Error(), "shrink") {
		t.Fatalf("shrink refusal diagnostic = %v, want a shrink-specific message", err)
	}
	// Lengthening is not a shrink: pinned 10 -> configured 12 loads.
	if _, err := LoadCheckpoint(path, sgn.PublicKey(), testPolicy(t, 12)); err != nil {
		t.Fatalf("a floor LENGTHENING from 10 y to 12 y was refused: %v", err)
	}
}

// TestSignBytesCarriesRetentionTag pins the domain separation against the
// OTHER live tag under the same key: the head envelope's.
func TestSignBytesCarriesRetentionTag(t *testing.T) {
	sb := testCheckpoint(t, 7).SignBytes()
	if !bytes.HasPrefix(sb, []byte("ocu-audit-retention/v1\x00")) {
		t.Fatal("checkpoint SignBytes does not start with the retention domain tag")
	}
	if bytes.HasPrefix(sb, []byte("ocu-audit-head/v1\x00")) {
		t.Fatal("checkpoint SignBytes carries the HEAD envelope tag; the two artifact " +
			"classes share a signed form under one key")
	}
}

// TestSignBytesBindsEveryAnchorField: flipping each boot-critical field must
// change the signed form, or a forged checkpoint could splice that field.
func TestSignBytesBindsEveryAnchorField(t *testing.T) {
	base := testCheckpoint(t, 7).SignBytes()
	mutate := map[string]func(*Checkpoint){
		"segment sha":    func(c *Checkpoint) { c.Segments[0].SHA256[0] ^= 1 },
		"chain tip":      func(c *Checkpoint) { c.ChainTips["control-plane"].Hash[0] ^= 1 },
		"tip sequence":   func(c *Checkpoint) { t := c.ChainTips["control-plane"]; t.Seq++; c.ChainTips["control-plane"] = t },
		"tree size":      func(c *Checkpoint) { c.TreeSize++ },
		"frontier":       func(c *Checkpoint) { c.Frontier[0][0] ^= 1 },
		"floor":          func(c *Checkpoint) { c.Policy.FloorYears++ },
		"record count":   func(c *Checkpoint) { c.Segments[1].RecordCount++ },
		"seal tree size": func(c *Checkpoint) { c.Segments[0].SealTreeSize++ },
		"seal tip": func(c *Checkpoint) {
			t := c.Segments[0].SealTips["control-plane"]
			t.Seq++
			c.Segments[0].SealTips["control-plane"] = t
		},
	}
	for name, mut := range mutate {
		cp := testCheckpoint(t, 7)
		mut(&cp)
		if bytes.Equal(cp.SignBytes(), base) {
			t.Fatalf("mutating %q left SignBytes unchanged; the checkpoint signature "+
				"does not bind that field", name)
		}
	}
}

// TestWriteCheckpointIsAtomic: a write into an unwritable directory leaves no
// final-name file behind (temp+rename, never write-in-place).
func TestWriteCheckpointIsAtomic(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "ro")
	if err := os.Mkdir(sub, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(sub, 0o700) })
	sgn, err := signer.Generate()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(sub, "retention-checkpoint.json")
	if err := WriteCheckpoint(path, testCheckpoint(t, 7), sgn); err == nil {
		t.Skip("directory unexpectedly writable (running as root?)")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("a failed checkpoint write left a file at the final name; " +
			"writes must be temp+rename")
	}
}

// TestWriteCheckpointRenamesOverReadOnlyFile distinguishes temp+rename from
// write-in-place: renaming over a 0400 file succeeds on POSIX, while opening
// it for in-place truncation fails. A write-in-place mutant reds here.
func TestWriteCheckpointRenamesOverReadOnlyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "retention-checkpoint.json")
	sgn, err := signer.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteCheckpoint(path, testCheckpoint(t, 7), sgn); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	next := testCheckpoint(t, 7)
	next.TreeSize = 99
	if err := WriteCheckpoint(path, next, sgn); err != nil {
		t.Fatalf("rewrite over a read-only checkpoint failed: %v — the write is "+
			"in-place, not temp+rename", err)
	}
	got, err := LoadCheckpoint(path, sgn.PublicKey(), testPolicy(t, 7))
	if err != nil {
		t.Fatal(err)
	}
	if got.TreeSize != 99 {
		t.Fatalf("rewritten checkpoint TreeSize = %d, want 99", got.TreeSize)
	}
}
