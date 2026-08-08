// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocsf

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// INV-8 acceptance anchor (component-07): the MessageEnvelope required fields
// are present and validated INDEPENDENT of the OCSF class, so the record
// survives transform to CEF/ECS/UDM. The gate is a "schema-conformance gate
// against the AuditEnvelope (the MessageEnvelope of the invariant text) in contracts/audit/audit-fanin.asyncapi.yaml."
//
// The decoder hand-maintains its required set (the PublishEnvelope struct plus
// validate()); the contract declares one. Nothing bound the two, so the decoder
// could drop a required field, or the contract grow one, and no test would
// notice — the drift a conformance gate exists to catch. These read the
// required set FROM the contract and bind the decoder to it, both directions.

const vendoredContract = "../../contracts/audit/audit-fanin.asyncapi.yaml"

// contractRequiredFields extracts the AuditEnvelope's `required:` flow
// sequence from the vendored contract. It reads the contract rather than
// mirroring it — a second hand-kept list would drift the same way the first
// did. The block is located by its schema title so a `required:` elsewhere in
// the document cannot be mistaken for it.
func contractRequiredFields(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(vendoredContract)
	if err != nil {
		t.Fatalf("read vendored contract: %v", err)
	}

	// The AuditEnvelope schema block, up to its required: line.
	block := regexp.MustCompile(`(?s)AuditEnvelope:.*?\n\s*required:\s*\[([^\]]*)\]`)
	m := block.FindSubmatch(raw)
	if m == nil {
		t.Fatal("AuditEnvelope required: list not found in the contract — the schema " +
			"moved or was renamed, and this conformance gate is now measuring nothing")
	}

	var out []string
	for _, f := range strings.Split(string(m[1]), ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	if len(out) < 5 {
		t.Fatalf("parsed only %d required fields; the flow-sequence format changed and "+
			"an under-parse would make this gate pass vacuously: %q", len(out), m[1])
	}
	sort.Strings(out)
	return out
}

// decoderRequiredFields lists the json tags the decoder treats as mandatory:
// the PublishEnvelope fields validate() rejects when empty. Payload is required
// too but is not a MessageEnvelope field (it carries the OCSF class, which the
// envelope is deliberately independent of), so it is excluded here.
func decoderRequiredFields() []string {
	out := []string{"trace_id", "session_id", "actor_id", "resource", "action", "outcome", "sequence"}
	sort.Strings(out)
	return out
}

// TestEnvelopeRequiredSetMatchesTheContract binds the decoder's mandatory set to
// the contract's, both directions. A field the contract requires that the
// decoder does not enforce is a record that can reach the store missing a field
// a downstream CEF/ECS/UDM transform needs; a field the decoder enforces that
// the contract does not declare is a source-facing rule the published contract
// never promised.
func TestEnvelopeRequiredSetMatchesTheContract(t *testing.T) {
	want := contractRequiredFields(t)
	got := decoderRequiredFields()

	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("the decoder enforces %v; the contract's AuditEnvelope requires %v — "+
			"the two mandatory sets have drifted", got, want)
	}
}

// TestDecoderRejectsAMissingRequiredField is the behavioural half: for EACH
// field the contract requires, a body omitting it must fail the decode. A
// set-equality check alone does not prove the decoder acts on every field — it
// could list a field and never enforce it.
func TestDecoderRejectsAMissingRequiredField(t *testing.T) {
	// A complete, valid body every case omits exactly one field from.
	full := map[string]string{
		"trace_id":   `"t"`,
		"session_id": `"s"`,
		"actor_id":   `"a"`,
		"resource":   `"r"`,
		"action":     `"act"`,
		"outcome":    `"success"`,
		"sequence":   `1`,
		"payload":    `{"k":"v"}`,
	}

	// Sanity: the full body decodes, or every omission below fails for the wrong
	// reason.
	if _, err := DecodePublish([]byte(assemble(full, ""))); err != nil {
		t.Fatalf("the complete body did not decode: %v", err)
	}

	for _, field := range contractRequiredFields(t) {
		t.Run(field, func(t *testing.T) {
			if _, err := DecodePublish([]byte(assemble(full, field))); err == nil {
				t.Errorf("a body omitting the required field %q decoded; the envelope's "+
					"mandatory-field guarantee does not survive transform without it", field)
			}
		})
	}
}

// assemble builds a JSON object from full, omitting the named field (empty omit
// keeps them all).
func assemble(full map[string]string, omit string) string {
	var parts []string
	for k, v := range full {
		if k == omit {
			continue
		}
		parts = append(parts, `"`+k+`":`+v)
	}
	sort.Strings(parts)
	return "{" + strings.Join(parts, ",") + "}"
}
