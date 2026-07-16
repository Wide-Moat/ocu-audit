// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package signer

import (
	"bytes"
	"testing"
)

func testEnvelope() HeadEnvelope {
	return HeadEnvelope{Date: "2026-07-16", TreeSize: 42, Head: bytes.Repeat([]byte{0xab}, 32)}
}

// TestSignVerifyRoundTrip asserts a signed head verifies against the signer's
// own pinned public key.
func TestSignVerifyRoundTrip(t *testing.T) {
	s, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	sh := s.Sign(testEnvelope())
	if err := Verify(sh, s.PublicKey()); err != nil {
		t.Fatalf("valid signature should verify: %v", err)
	}
}

// TestVerifyRejectsWrongKey is the signer-real anchor: verifying against a
// DIFFERENT pinned key fails. Verify never asserts "signature present".
func TestVerifyRejectsWrongKey(t *testing.T) {
	s, _ := Generate()
	other, _ := Generate()
	sh := s.Sign(testEnvelope())
	if err := Verify(sh, other.PublicKey()); err == nil {
		t.Fatal("signature must not verify against a different pinned key")
	}
}

// TestVerifyRejectsSwappedEmbeddedKey asserts an attacker cannot swap both the
// embedded public key AND signature to a key they control while the pin stays
// fixed: Verify checks the embedded key equals the pin first.
func TestVerifyRejectsSwappedEmbeddedKey(t *testing.T) {
	pinned, _ := Generate()
	attacker, _ := Generate()
	sh := attacker.Sign(testEnvelope()) // attacker self-signs, embeds attacker pubkey
	if err := Verify(sh, pinned.PublicKey()); err == nil {
		t.Fatal("a head signed by a non-pinned key must be rejected")
	}
}

// TestVerifyRejectsTamperedEnvelope asserts mutating the head bytes after
// signing fails verification.
func TestVerifyRejectsTamperedEnvelope(t *testing.T) {
	s, _ := Generate()
	sh := s.Sign(testEnvelope())
	sh.Envelope.Head[0] ^= 0xff
	if err := Verify(sh, s.PublicKey()); err == nil {
		t.Fatal("tampered envelope must fail signature verification")
	}
}

// TestVerifyRejectsTamperedTreeSize asserts the tree size is bound into the
// signed bytes: changing it after signing fails.
func TestVerifyRejectsTamperedTreeSize(t *testing.T) {
	s, _ := Generate()
	sh := s.Sign(testEnvelope())
	sh.Envelope.TreeSize = 43
	if err := Verify(sh, s.PublicKey()); err == nil {
		t.Fatal("tampered tree size must fail signature verification")
	}
}

// TestMarshalRoundTrip asserts the signed head survives JSON persistence.
func TestMarshalRoundTrip(t *testing.T) {
	s, _ := Generate()
	sh := s.Sign(testEnvelope())
	b, err := MarshalSignedHead(sh)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalSignedHead(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(got, s.PublicKey()); err != nil {
		t.Fatalf("round-tripped signed head should verify: %v", err)
	}
}
