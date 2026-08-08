// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package edgetail converts the egress edge's Envoy JSON access log into
// per-connection OCSF publishes on the egress-edge fan-in channel (A6,
// component-06 P6-R1: one OCSF event per connection). The edge itself stays
// stock Envoy — its only OCU-authored content is configuration, including the
// json_format whose field set THIS converter pins; the collector is
// pipeline-family code, so it lives here, not on the edge.
package edgetail

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Wide-Moat/ocu-audit/internal/ocsf"
)

// accessLogEntry is the pinned envoy.yaml json_format field set. Decoding
// refuses unknown fields: a drifted format must fail loudly, not convert into
// hollow records that look like audit coverage.
type accessLogEntry struct {
	StartTime           string `json:"start_time"`
	Method              string `json:"method"`
	Path                string `json:"path"`
	Authority           string `json:"authority"`
	ResponseCode        int    `json:"response_code"`
	ResponseCodeDetails string `json:"response_code_details"`
	BytesSent           int64  `json:"bytes_sent"`
	BytesReceived       int64  `json:"bytes_received"`
	DurationMillis      int64  `json:"duration_ms"`
	XRequestID          string `json:"x_request_id"`
	SessionID           string `json:"session_id"`
}

// Convert turns one access-log line into the egress-edge channel's publish
// envelope carrying an OCSF 4002 (HTTP Activity) payload. The sequence is the
// caller's monotonic counter (the tailer's durable cursor); the source label
// is the CHANNEL's, bound by the fan-in, never set here (INV-1). A pre-auth
// deny has no session and the empty session survives as empty — inventing
// one would forge attribution (NFR-SEC-43).
func Convert(line []byte, sequence uint64) (*ocsf.PublishEnvelope, error) {
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	var e accessLogEntry
	if err := dec.Decode(&e); err != nil {
		return nil, fmt.Errorf("edgetail: decode access-log line: %w", err)
	}
	// Envoy renders an absent operator value as the "-" sentinel (a header
	// the request never carried, or jwt_authn dynamic metadata on a pre-auth
	// deny). Normalize it to empty on the ATTRIBUTION fields: a deny
	// attributed to a session literally named "-" would be a forged-looking
	// actor (NFR-SEC-43). Request-line fields (method/path/authority) are
	// always present and stay as-is.
	if e.SessionID == "-" {
		e.SessionID = ""
	}
	if e.XRequestID == "-" {
		e.XRequestID = ""
	}
	if e.Method == "" && e.Authority == "" && e.XRequestID == "" {
		return nil, fmt.Errorf("edgetail: line carries none of the pinned fields; the json_format has drifted")
	}

	outcome := ocsf.OutcomeSuccess
	statusID := 1 // OCSF Success
	if e.ResponseCode >= 400 {
		outcome = ocsf.OutcomeFailure
		statusID = 2 // OCSF Failure
	}

	// The occurred-at time is the SOURCE's clock, recorded on the payload;
	// the pipeline stamps the trusted IngestTime at commit (NFR-SEC-48).
	var occurredMillis int64
	if ts, err := time.Parse(time.RFC3339Nano, e.StartTime); err == nil {
		occurredMillis = ts.UnixMilli()
	}

	// Minimal class-correct OCSF 4002: the discriminator, the activity, the
	// request/response objects, and the status a SIEM consumer keys on
	// (ADR-0044: the class follows the record).
	payload, err := json.Marshal(map[string]any{
		"class_uid":     4002,
		"category_uid":  4,
		"activity_id":   activityID(e.Method),
		"time":          occurredMillis,
		"status_id":     statusID,
		"status_detail": e.ResponseCodeDetails,
		"http_request": map[string]any{
			"http_method": e.Method,
			"url": map[string]any{
				"hostname": e.Authority,
				"path":     e.Path,
			},
		},
		"http_response": map[string]any{
			"code": e.ResponseCode,
		},
		"traffic": map[string]any{
			"bytes_in":  e.BytesReceived,
			"bytes_out": e.BytesSent,
		},
		"duration": e.DurationMillis,
	})
	if err != nil {
		return nil, fmt.Errorf("edgetail: encode payload: %w", err)
	}

	return &ocsf.PublishEnvelope{
		TraceID:   e.XRequestID,
		SessionID: e.SessionID,
		ActorID:   e.SessionID, // the session IS the actor of an egress connection; empty pre-auth
		Resource:  e.Authority,
		Action:    "egress.http",
		Outcome:   outcome,
		Sequence:  sequence,
		Payload:   payload,
	}, nil
}

// activityID maps the HTTP method to the OCSF 4002 activity enum (Connect=1
// is not modelled by method; OCSF 4002 activities are request-method-shaped:
// 1 Connect, 2 Delete, 3 Get, 4 Head, 5 Options, 6 Post, 7 Put, 8 Trace,
// 99 Other).
func activityID(method string) int {
	switch method {
	case "CONNECT":
		return 1
	case "DELETE":
		return 2
	case "GET":
		return 3
	case "HEAD":
		return 4
	case "OPTIONS":
		return 5
	case "POST":
		return 6
	case "PUT":
		return 7
	case "TRACE":
		return 8
	default:
		return 99
	}
}
