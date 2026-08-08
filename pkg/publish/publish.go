// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package publish is the host-side source client for the ocu-audit fan-in
// (component-07 F10). A source constructs a Client bound to one channel address
// over mutual TLS, then Publish-es OCSF events. The wire binding is frozen in
// docs/wire-surface.md and contracts/audit/audit-fanin.asyncapi.yaml; this
// client speaks exactly that binding and no more.
//
// The client re-declares the Envelope shape rather than importing the pipeline's
// internal/ocsf type: a source depends on the frozen wire contract, not on the
// server's internal representation. The two are kept in lockstep by the
// contract, and a drift test in a source repo pins them.
//
// Fail-closed is the whole point (INV-4 / P7-R3): Publish returns a non-nil
// error unless the ingest replied 200, which the service issues only after the
// write-ahead log fsync succeeds. A caller that couples a privileged action to
// Publish therefore denies the action when the central commit cannot be
// guaranteed. Publish never swallows a non-200.
package publish

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// routePrefix mirrors the server's ingest route prefix (internal/ingest).
const routePrefix = "/v1alpha/audit/"

// maxErrBody bounds how much of a non-200 response body the client reads back
// into the returned error, so a hostile or broken ingest cannot make the
// source allocate without limit while it is trying to fail closed.
const maxErrBody = 4 << 10 // 4 KiB

// Outcome is the OCSF activity outcome a source reports. It mirrors the frozen
// wire enum; the server rejects any other value with 400.
type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailure Outcome = "failure"
	OutcomeUnknown Outcome = "unknown"
)

// Envelope is the wire shape a source POSTs, per docs/wire-surface.md. It
// deliberately carries no source, prev_hash, or chain_hash field: the OCSF
// source is the verified client-certificate common name (INV-1) and the chain
// linkage is authored by the pipeline (INV-3). Setting any of those is
// impossible here by construction, so a source cannot smuggle a chain claim.
type Envelope struct {
	TraceID   string          `json:"trace_id"`
	SessionID string          `json:"session_id"`
	ActorID   string          `json:"actor_id"`
	Resource  string          `json:"resource"`
	Action    string          `json:"action"`
	Outcome   Outcome         `json:"outcome"`
	Sequence  uint64          `json:"sequence"`
	Payload   json.RawMessage `json:"payload"`
}

// Client publishes to one channel address of the ocu-audit fan-in over mTLS.
// It is safe for concurrent use by multiple goroutines (http.Client is).
type Client struct {
	httpc   *http.Client
	baseURL string // scheme+host, no trailing slash, e.g. https://audit:8443
	channel string // e.g. audit.ingest.control-plane
}

// Config configures a Client. The TLS config MUST present the source's client
// certificate; the ingest runs RequireAndVerifyClientCert and derives the OCSF
// source from the presented certificate's common name. A Config without a
// client certificate produces a client whose Publish calls fail with 401.
type Config struct {
	// BaseURL is the ingest origin, e.g. "https://audit:8443". Required.
	BaseURL string
	// Channel is the contract channel address, e.g.
	// "audit.ingest.control-plane". Required. It must match the source label
	// the peer's certificate is authorized for, or the ingest returns 403.
	Channel string
	// TLS carries the source's client certificate and the CA that verifies the
	// ingest's server certificate. Required for a live ingest.
	TLS *tls.Config
}

// New constructs a Client. It validates that BaseURL, Channel, and TLS are set;
// a missing field is a construction error, not a deferred publish failure.
func New(cfg Config) (*Client, error) {
	switch {
	case cfg.BaseURL == "":
		return nil, errors.New("publish: BaseURL is required")
	case cfg.Channel == "":
		return nil, errors.New("publish: Channel is required")
	case cfg.TLS == nil:
		return nil, errors.New("publish: TLS config is required (mTLS client certificate)")
	}
	return &Client{
		httpc:   &http.Client{Transport: &http.Transport{TLSClientConfig: cfg.TLS}},
		baseURL: strings.TrimRight(cfg.BaseURL, "/"),
		channel: cfg.Channel,
	}, nil
}

// NewWithHTTPClient constructs a Client over a caller-supplied *http.Client. It
// exists for tests (a test server + its client) and for callers that need to
// tune timeouts or transports; the caller owns the TLS wiring on that client.
func NewWithHTTPClient(httpc *http.Client, baseURL, channel string) (*Client, error) {
	switch {
	case httpc == nil:
		return nil, errors.New("publish: http client is required")
	case baseURL == "":
		return nil, errors.New("publish: baseURL is required")
	case channel == "":
		return nil, errors.New("publish: channel is required")
	}
	return &Client{httpc: httpc, baseURL: strings.TrimRight(baseURL, "/"), channel: channel}, nil
}

// Publish POSTs one envelope to the channel and returns nil only on a 200 ack.
// Any other status, a transport error, or an unreadable response yields a
// non-nil error: the event is not committed and the caller must not treat the
// audited action as durable. On a retriable status (503, or a transport error)
// the caller should retry with the SAME sequence; the ingest is idempotent on
// a duplicate sequence and re-acks 200 without re-appending.
func (c *Client) Publish(ctx context.Context, env Envelope) error {
	body, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("publish: marshal envelope: %w", err)
	}
	url := c.baseURL + routePrefix + c.channel
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("publish: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpc.Do(req)
	if err != nil {
		// Transport failure = not committed. Fail closed.
		return fmt.Errorf("publish: %s seq=%d: transport: %w", c.channel, env.Sequence, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return nil
	}
	// Non-200 = not committed. Read a bounded slice of the body for context and
	// return an error that names the status so the caller's fail-closed branch
	// can log or retry. Never return nil here.
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrBody))
	return &PublishError{
		Channel:  c.channel,
		Sequence: env.Sequence,
		Status:   resp.StatusCode,
		Body:     strings.TrimSpace(string(snippet)),
	}
}

// PublishError is a non-200 response from the ingest. It carries the status so
// callers can distinguish a retriable 503 / 429 (fairness-shaped, NFR-SEC-56) /
// 409 from a terminal 400 / 401 / 403.
type PublishError struct {
	Channel  string
	Sequence uint64
	Status   int
	Body     string
}

func (e *PublishError) Error() string {
	return fmt.Sprintf("publish: %s seq=%d: ingest returned %d %s: %s",
		e.Channel, e.Sequence, e.Status, http.StatusText(e.Status), e.Body)
}

// Retriable reports whether the source should retry with the same sequence. A
// 503 (fsync fault, not committed) is retriable; a transport error is handled
// separately (it is not a *PublishError). A 4xx is terminal: the envelope or
// the peer authorization is wrong, and retrying the same bytes will not help.
func (e *PublishError) Retriable() bool {
	return e.Status == http.StatusServiceUnavailable
}
