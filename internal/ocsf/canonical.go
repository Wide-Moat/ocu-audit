// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocsf

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"sort"
)

// writeU64 appends a fixed-width big-endian uint64. Fixed width means the
// value is self-delimiting and needs no length prefix.
func writeU64(b *bytes.Buffer, v uint64) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	b.Write(buf[:])
}

// writeField appends a length-prefixed byte field: uint64-BE length then the
// bytes. Length-prefixing is what makes the concatenation injective: without
// it, ("ab","c") and ("a","bc") would encode identically and two distinct
// records could share a canonical form (a chain-forgery seam).
func writeField(b *bytes.Buffer, v []byte) {
	writeU64(b, uint64(len(v)))
	b.Write(v)
}

// canonicalJSON re-encodes an arbitrary JSON value into a deterministic form:
// object keys sorted, insignificant whitespace removed. Two byte sequences that
// are the same JSON value therefore canonicalize identically, so the chain hash
// does not depend on a source's key ordering or spacing. Invalid JSON (already
// rejected at decode) falls back to the raw bytes so the function is total.
func canonicalJSON(raw []byte) []byte {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return raw
	}
	out, err := marshalCanonical(v)
	if err != nil {
		return raw
	}
	return out
}

// marshalCanonical serializes a decoded JSON value with sorted object keys.
// json.Marshal already sorts map[string]any keys, but it is explicit here so a
// future encoder change cannot silently alter the chain-input encoding.
func marshalCanonical(v any) ([]byte, error) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b bytes.Buffer
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			kb, err := json.Marshal(k)
			if err != nil {
				return nil, err
			}
			b.Write(kb)
			b.WriteByte(':')
			vb, err := marshalCanonical(t[k])
			if err != nil {
				return nil, err
			}
			b.Write(vb)
		}
		b.WriteByte('}')
		return b.Bytes(), nil
	case []any:
		var b bytes.Buffer
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			eb, err := marshalCanonical(e)
			if err != nil {
				return nil, err
			}
			b.Write(eb)
		}
		b.WriteByte(']')
		return b.Bytes(), nil
	default:
		return json.Marshal(v)
	}
}
