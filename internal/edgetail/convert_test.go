// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package edgetail

import (
	"encoding/json"
	"strings"
	"testing"
)

// A6 (component-06 P6-R1): one OCSF event per edge connection. The edge stays
// stock Envoy — config writes a JSON access log — and THIS package, pipeline-
// family code, converts each line to the egress-edge channel's HttpActivity
// (OCSF 4002) publish. The converter defines the log-format contract the
// envoy.yaml json_format must emit; these goldens ARE that contract.

const allowedLine = `{"start_time":"2026-08-08T10:00:00.123Z","method":"GET","path":"/v1/filestore/objects/abc","authority":"filestore.internal:8443","response_code":200,"response_code_details":"via_upstream","bytes_sent":512,"bytes_received":0,"duration_ms":42,"x_request_id":"req-123","session_id":"sess-9"}`

// deniedLine carries session_id "-": ENVOY'S missing-value sentinel, which is
// what a real pre-auth deny emits for the jwt_authn dynamic-metadata operator
// (the metadata namespace does not exist before validation succeeds). The
// converter must normalize it to empty — a fixture with a hand-written ""
// would green while the live wire attributed denies to a session named "-".
const deniedLine = `{"start_time":"2026-08-08T10:00:01.000Z","method":"POST","path":"/v1/filestore/objects","authority":"filestore.internal:8443","response_code":401,"response_code_details":"jwt_authn_access_denied","bytes_sent":0,"bytes_received":128,"duration_ms":1,"x_request_id":"req-124","session_id":"-"}`

func TestConvertAllowedConnection(t *testing.T) {
	env, err := Convert([]byte(allowedLine), 7)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if env.Sequence != 7 {
		t.Fatalf("sequence = %d, want the caller's 7", env.Sequence)
	}
	if env.TraceID != "req-123" || env.SessionID != "sess-9" {
		t.Fatalf("attribution: trace=%q session=%q", env.TraceID, env.SessionID)
	}
	if env.Resource != "filestore.internal:8443" {
		t.Fatalf("resource = %q, want the upstream authority", env.Resource)
	}
	if env.Action != "egress.http" {
		t.Fatalf("action = %q", env.Action)
	}
	if env.Outcome != "success" {
		t.Fatalf("outcome = %q for a 200", env.Outcome)
	}

	var payload map[string]any
	if err := json.Unmarshal(env.Payload, &payload); err != nil {
		t.Fatalf("payload: %v", err)
	}
	// The OCSF 4002 discriminator and the request/response objects — the
	// class-bearing fields a SIEM consumer keys on (ADR-0044: the class
	// follows the record; 4002 is HTTP Activity).
	if uid, _ := payload["class_uid"].(float64); uid != 4002 {
		t.Fatalf("class_uid = %v, want 4002", payload["class_uid"])
	}
	req, _ := payload["http_request"].(map[string]any)
	if req == nil || req["http_method"] != "GET" {
		t.Fatalf("http_request = %v", payload["http_request"])
	}
	resp, _ := payload["http_response"].(map[string]any)
	if resp == nil {
		t.Fatal("no http_response object")
	}
	if code, _ := resp["code"].(float64); code != 200 {
		t.Fatalf("http_response.code = %v", resp["code"])
	}
	if payload["time"] == nil {
		t.Fatal("payload carries no occurred-at time; the source clock is the " +
			"RECORDED time (the pipeline stamps the trusted IngestTime separately)")
	}
}

// TestConvertDeniedConnectionMapsRefusalToFailure: the deny is the event that
// matters in a dispute (P6-R1) — outcome failure, the deny reason in
// status_detail, and the empty session survives as empty (a pre-auth deny has
// no session; inventing one would forge attribution).
func TestConvertDeniedConnectionMapsRefusalToFailure(t *testing.T) {
	env, err := Convert([]byte(deniedLine), 8)
	if err != nil {
		t.Fatal(err)
	}
	if env.Outcome != "failure" {
		t.Fatalf("outcome = %q for a 401 deny", env.Outcome)
	}
	if env.SessionID != "" {
		t.Fatalf("session = %q for a pre-auth deny, want empty — the Envoy \"-\" "+
			"missing-value sentinel must be normalized, never carried as an actor", env.SessionID)
	}
	var payload map[string]any
	if err := json.Unmarshal(env.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if sd, _ := payload["status_detail"].(string); sd != "jwt_authn_access_denied" {
		t.Fatalf("status_detail = %v, want the deny reason", payload["status_detail"])
	}
	if payload["status_id"] != float64(2) {
		t.Fatalf("status_id = %v, want 2 (Failure)", payload["status_id"])
	}
}

// TestConvertRefusesGarbage: a malformed line errors (the tailer skips-and-
// counts it; silently converting garbage would forge an audit record).
func TestConvertRefusesGarbage(t *testing.T) {
	if _, err := Convert([]byte("not json at all"), 1); err == nil {
		t.Fatal("garbage converted")
	}
	if _, err := Convert([]byte(`{"unknown_field":1}`), 1); err == nil {
		t.Fatal("a line missing every expected field converted; the log format " +
			"contract has drifted and the tailer must say so, not emit hollow records")
	}
}

// TestConvertRefusesUnknownLogFields: an unexpected field means the envoy.yaml
// json_format and this converter have drifted — refuse loudly.
func TestConvertRefusesUnknownLogFields(t *testing.T) {
	drifted := strings.Replace(allowedLine, `"session_id":"sess-9"`, `"session_id":"sess-9","new_field":1`, 1)
	if _, err := Convert([]byte(drifted), 1); err == nil {
		t.Fatal("a log line with an unknown field converted; format drift must refuse")
	}
}
