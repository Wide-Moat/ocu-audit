// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package signer

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// fixedSeedSigner loads a signer whose key derives from a deterministic seed
// (bytes 1..32), so signatures are reproducible test vectors.
func fixedSeedSigner(t *testing.T) *Signer {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	p := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(p, priv, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := LoadPrivateKey(p)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestSignBytesKnownAnswer pins the canonical signed-byte encoding to a fixed
// vector. This kills a mutant in SignBytes (dropped domain tag, wrong length
// prefix, skipped tree-size, reordered fields): Sign and Verify both call
// SignBytes and would agree with a mutated encoding symmetrically, but this
// fixed vector reds.
func TestSignBytesKnownAnswer(t *testing.T) {
	head := make([]byte, 32)
	for i := range head {
		head[i] = 0xab
	}
	env := HeadEnvelope{Date: "2026-07-16", TreeSize: 42, Head: head}
	want := "6f63752d61756469742d686561642f763100000000000000000a323032362d30372d3136000000000000002a0000000000000020abababababababababababababababababababababababababababababababab"
	if got := hex.EncodeToString(env.SignBytes()); got != want {
		t.Fatalf("SignBytes vector mismatch:\n got %s\nwant %s", got, want)
	}
}

// TestSignatureKnownAnswer pins the Ed25519 signature and public key for the
// fixed-seed key over the fixed envelope. It kills a mutant that alters the
// signing input or the key derivation.
func TestSignatureKnownAnswer(t *testing.T) {
	s := fixedSeedSigner(t)
	head := make([]byte, 32)
	for i := range head {
		head[i] = 0xab
	}
	sh := s.Sign(HeadEnvelope{Date: "2026-07-16", TreeSize: 42, Head: head})

	wantPub := "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664"
	if got := hex.EncodeToString(sh.PublicKey); got != wantPub {
		t.Fatalf("public key: got %s want %s", got, wantPub)
	}
	wantSig := "aaaf54fc01fce25ae5e84c767261ed154f355501f11f2523652af37d6e7769f6c44aea46954e71ee1fcb12c6f9bf979c84b8157d3771df5603eb9a0c0773150a"
	if got := hex.EncodeToString(sh.Signature); got != wantSig {
		t.Fatalf("signature: got %s want %s", got, wantSig)
	}
	// And it verifies against the fixed pinned key.
	pub, _ := hex.DecodeString(wantPub)
	if err := Verify(sh, pub); err != nil {
		t.Fatalf("fixed-vector signature must verify: %v", err)
	}
}

// TestSignBytesDependsOnEachField asserts SignBytes changes when the date, tree
// size, or head changes independently, killing a mutant that drops any field.
func TestSignBytesDependsOnEachField(t *testing.T) {
	head := make([]byte, 32)
	base := HeadEnvelope{Date: "2026-07-16", TreeSize: 42, Head: head}.SignBytes()

	if hex.EncodeToString(HeadEnvelope{Date: "2026-07-17", TreeSize: 42, Head: head}.SignBytes()) == hex.EncodeToString(base) {
		t.Fatal("SignBytes must depend on date")
	}
	if hex.EncodeToString(HeadEnvelope{Date: "2026-07-16", TreeSize: 43, Head: head}.SignBytes()) == hex.EncodeToString(base) {
		t.Fatal("SignBytes must depend on tree size")
	}
	head2 := make([]byte, 32)
	head2[0] = 1
	if hex.EncodeToString(HeadEnvelope{Date: "2026-07-16", TreeSize: 42, Head: head2}.SignBytes()) == hex.EncodeToString(base) {
		t.Fatal("SignBytes must depend on head")
	}
}

// TestPublicKeyMatchesPrivate asserts PublicKey derives from the loaded private
// key (kills a mutant that returns a wrong slice).
func TestPublicKeyMatchesPrivate(t *testing.T) {
	s := fixedSeedSigner(t)
	pub := s.PublicKey()
	// Signing then verifying against this exact pub must succeed.
	sh := s.Sign(HeadEnvelope{Date: "d", TreeSize: 1, Head: make([]byte, 32)})
	if err := Verify(sh, pub); err != nil {
		t.Fatalf("PublicKey must be the verifying key: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("public key length %d", len(pub))
	}
}
