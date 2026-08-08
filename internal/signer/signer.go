// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package signer signs the daily Merkle-head submission envelope with a
// host-local Ed25519 key (component-07 INV-7, ADR-0009 solo-shelf envelope-key
// custody). The pipeline signs ONLY the submission envelope, not the head
// itself; the transparency-log operator signs the head. On the minimal shelf
// the key is host-local; the full shelf swaps in an HSM-rooted key behind the
// same interface.
//
// Uses crypto/ed25519 from the standard library only.
package signer

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// HeadEnvelope is the submission envelope carried to the transparency log. It
// binds the head to a tree size and a UTC date so a head cannot be replayed
// against a different day or size. SignBytes is the canonical byte string the
// Ed25519 signature covers.
type HeadEnvelope struct {
	// Date is the head's UTC calendar day, RFC-3339 date (YYYY-MM-DD).
	Date string `json:"date"`
	// TreeSize is the number of leaves the head commits to.
	TreeSize uint64 `json:"tree_size"`
	// Head is the Merkle root bytes.
	Head []byte `json:"head"`
}

// SignBytes returns the canonical, length-prefixed byte string signed for this
// envelope. Length-prefixing each field keeps the encoding injective so two
// distinct envelopes cannot share a signed form.
func (e HeadEnvelope) SignBytes() []byte {
	var buf []byte
	appendField := func(b, v []byte) []byte {
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(len(v)))
		b = append(b, l[:]...)
		return append(b, v...)
	}
	buf = append(buf, []byte("ocu-audit-head/v1\x00")...)
	buf = appendField(buf, []byte(e.Date))
	var sz [8]byte
	binary.BigEndian.PutUint64(sz[:], e.TreeSize)
	buf = append(buf, sz[:]...)
	buf = appendField(buf, e.Head)
	return buf
}

// SignedHead is an envelope plus its detached Ed25519 signature and the public
// key that verifies it. The verifier pins the expected public key out-of-band
// and rejects a signed head whose PublicKey does not match the pin.
type SignedHead struct {
	Envelope  HeadEnvelope `json:"envelope"`
	Signature []byte       `json:"signature"`
	PublicKey []byte       `json:"public_key"`
}

// Signer holds the host-local private key.
type Signer struct {
	priv ed25519.PrivateKey
}

// Generate mints a fresh key pair (used to bootstrap a solo-shelf deployment).
func Generate() (*Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("signer: generate key: %w", err)
	}
	return &Signer{priv: priv}, nil
}

// LoadPrivateKey loads a raw 64-byte Ed25519 private key from a file.
func LoadPrivateKey(path string) (*Signer, error) {
	// #nosec G304 -- path is the operator's -sign-key flag. The signing key
	// lives where the deployment puts it; this is key loading, not caller-
	// controlled file access.
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("signer: read key %q: %w", path, err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("signer: key %q is %d bytes, want %d",
			path, len(raw), ed25519.PrivateKeySize)
	}
	return &Signer{priv: ed25519.PrivateKey(raw)}, nil
}

// PublicKey returns the signer's public key bytes.
func (s *Signer) PublicKey() []byte {
	return append([]byte(nil), s.priv.Public().(ed25519.PublicKey)...)
}

// WritePrivateKey persists the raw private key with 0600 perms.
func (s *Signer) WritePrivateKey(path string) error {
	return os.WriteFile(path, s.priv, 0o600)
}

// Sign produces a SignedHead over the envelope. The signature covers
// envelope.SignBytes(), and the signer's public key is embedded so a verifier
// can pin it.
func (s *Signer) Sign(e HeadEnvelope) SignedHead {
	sig := ed25519.Sign(s.priv, e.SignBytes())
	return SignedHead{Envelope: e, Signature: sig, PublicKey: s.PublicKey()}
}

// Verify checks a SignedHead against a pinned public key. It fails if the
// embedded public key does not equal the pin (a wrong-key or swapped-key
// attack), or if the Ed25519 signature does not verify over the envelope's
// canonical bytes. It never asserts merely that a signature is "present".
func Verify(sh SignedHead, pinnedPub []byte) error {
	if len(pinnedPub) != ed25519.PublicKeySize {
		return fmt.Errorf("signer: pinned public key is %d bytes, want %d",
			len(pinnedPub), ed25519.PublicKeySize)
	}
	if !bytesEqual(sh.PublicKey, pinnedPub) {
		return errors.New("signer: signed-head public key does not match the pinned key")
	}
	if len(sh.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("signer: signature is %d bytes, want %d",
			len(sh.Signature), ed25519.SignatureSize)
	}
	if !ed25519.Verify(ed25519.PublicKey(pinnedPub), sh.Envelope.SignBytes(), sh.Signature) {
		return errors.New("signer: Ed25519 signature verification failed")
	}
	return nil
}

// MarshalSignedHead / UnmarshalSignedHead persist the signed head as JSON.
func MarshalSignedHead(sh SignedHead) ([]byte, error) {
	return json.MarshalIndent(sh, "", "  ")
}

// UnmarshalSignedHead parses a persisted signed head.
func UnmarshalSignedHead(raw []byte) (SignedHead, error) {
	var sh SignedHead
	if err := json.Unmarshal(raw, &sh); err != nil {
		return SignedHead{}, fmt.Errorf("signer: unmarshal signed head: %w", err)
	}
	return sh, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// SignMessage signs an envelope's canonical bytes directly. Every envelope
// type embeds its own domain tag inside its SignBytes encoding (the
// HeadEnvelope pattern), so two artifact classes can never share a signed
// form even under this one key (ADR-0045: the retention checkpoint signs
// under "ocu-audit-retention/v1" with the same host-local key).
func (s *Signer) SignMessage(canonical []byte) []byte {
	return ed25519.Sign(s.priv, canonical)
}

// VerifyMessage checks a detached signature over an envelope's canonical
// bytes against a pinned public key.
func VerifyMessage(pinnedPub, canonical, sig []byte) error {
	if len(pinnedPub) != ed25519.PublicKeySize {
		return fmt.Errorf("signer: pinned public key is %d bytes, want %d",
			len(pinnedPub), ed25519.PublicKeySize)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("signer: signature is %d bytes, want %d",
			len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(ed25519.PublicKey(pinnedPub), canonical, sig) {
		return errors.New("signer: Ed25519 signature verification failed")
	}
	return nil
}
