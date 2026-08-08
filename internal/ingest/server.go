// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingest

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/Wide-Moat/ocu-audit/internal/ocsf"
	"github.com/Wide-Moat/ocu-audit/internal/store"
)

// maxBody bounds a single publish body (NFR-SEC-51 defensive cap).
const maxBody = 4 << 20 // 4 MiB

// routePrefix is the URL path prefix for channel routes; the channel address
// is the remaining path segment.
const routePrefix = "/v1alpha/audit/"

// PeerVerifier extracts the verified peer identity (certificate common name)
// from a request's TLS state. The production verifier reads the mTLS client
// cert; a test verifier injects a synthetic peer without a real TLS handshake.
type PeerVerifier interface {
	// PeerCN returns the verified peer common name and true, or false if the
	// request carries no verified client certificate.
	PeerCN(r *http.Request) (string, bool)
}

// MTLSPeerVerifier reads the peer CN from the verified client certificate chain
// of the TLS connection. It requires the server to have run mTLS with
// ClientAuth=RequireAndVerifyClientCert so VerifiedChains is populated.
type MTLSPeerVerifier struct{}

// PeerCN returns the leaf certificate subject common name from the verified
// chain. It never falls back to an unverified header (that would let a peer
// spoof its identity), so the source binding is host-attested (INV-1).
func (MTLSPeerVerifier) PeerCN(r *http.Request) (string, bool) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
		return "", false
	}
	chain0 := r.TLS.VerifiedChains[0]
	if len(chain0) == 0 {
		return "", false
	}
	cn := chain0[0].Subject.CommonName
	if cn == "" {
		return "", false
	}
	return cn, true
}

// selfEmitSource is the host-attested source label for the pipeline's own
// internally-originated channel (audit.ingest.audit-pipeline). It has no mTLS
// wire peer: the pipeline authors these records itself, so INV-1 holds by the
// pipeline being the observer. saturationAction labels a per-source saturation
// event; the saturation PAYLOAD schema is Open-Q #5 (OCSF v1.x ships no
// saturation class), so the record carries a stable action and names the
// saturated source, but asserts no OCSF class_uid.
const (
	selfEmitSource   = "audit-pipeline"
	saturationAction = "ingest.saturation"
)

// Server is the ingest HTTP handler.
type Server struct {
	store    *store.Store
	authz    *PeerChannelAuthz
	verifier PeerVerifier

	// limiter applies per-source ingest fairness before admission (NFR-SEC-56).
	// nil disables fairness (the plain NewServer path), so a source is never
	// shaped and no saturation is self-emitted.
	limiter *limiter
	// selfEmitSeq is the pipeline's own monotonic sequence for self-emitted
	// records (saturation events). Guarded by selfEmitMu so concurrent shaped
	// requests do not mint a duplicate or regressing sequence.
	selfEmitMu  sync.Mutex
	selfEmitSeq uint64
}

// NewServer builds the ingest handler with fairness disabled.
func NewServer(st *store.Store, authz *PeerChannelAuthz, v PeerVerifier) *Server {
	return &Server{store: st, authz: authz, verifier: v}
}

// NewServerWithFairness builds the ingest handler with per-source ingest
// fairness (NFR-SEC-56): a source exceeding share is rate-shaped, counted, and
// its over-share onset self-emits a saturation event on the pipeline channel.
func NewServerWithFairness(st *store.Store, authz *PeerChannelAuthz, v PeerVerifier, share FairnessShare, clk clock) *Server {
	return &Server{
		store:    st,
		authz:    authz,
		verifier: v,
		limiter:  newLimiter(share, clk),
	}
}

// Handler returns the routed http.Handler. One route per channel address; a
// POST to /v1alpha/audit/<address>.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(routePrefix, s.handlePublish)
	return mux
}

func (s *Server) handlePublish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	address := strings.TrimPrefix(r.URL.Path, routePrefix)
	source, known := sourceForAddress(address)
	if !known {
		http.Error(w, "unknown channel", http.StatusNotFound)
		return
	}

	// Host-attested peer identity. No verified client cert => 401. The source
	// label is taken from the CHANNEL, never the payload (INV-1).
	peerCN, ok := s.verifier.PeerCN(r)
	if !ok {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}

	// INV-2: a peer may publish only to its authorized channel(s). A
	// cross-channel publish is rejected; nothing is admitted.
	if !s.authz.Authorized(peerCN, address) {
		http.Error(w, "peer not authorized for this channel", http.StatusForbidden)
		return
	}

	// Per-source ingest fairness, applied AFTER authz and BEFORE admission
	// (NFR-SEC-56, component-07 INV-6). Keyed to the host-attested source (the
	// channel binding), never the payload. Over-share is rate-SHAPED, not
	// dropped: a shaped request gets a retryable 429 and nothing is admitted, so
	// the committed chain keeps its per-source sequence gap-free. The first
	// over-share in an episode self-emits a saturation event on the pipeline's
	// own channel; co-tenant sources are unaffected (independent buckets).
	if s.limiter != nil && !s.limiter.admit(source) {
		if s.limiter.saturationOnset(source) {
			s.selfEmitSaturation(source)
		}
		w.Header().Set("Retry-After", "1")
		http.Error(w, "ingest share exceeded; retry", http.StatusTooManyRequests)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}

	env, err := ocsf.DecodePublish(body)
	if err != nil {
		// A payload carrying a source/prev_hash/chain_hash key lands here
		// (DisallowUnknownFields), as does any bounds or schema violation.
		http.Error(w, "invalid publish envelope", http.StatusBadRequest)
		return
	}

	rec, err := s.store.Admit(source, env)
	switch {
	case err == nil:
		// Durably committed (fsync-then-ack): 200 is the ack (INV-4).
		w.Header().Set("X-Audit-Chain-Hash", hexEncode(rec.ChainHash))
		w.WriteHeader(http.StatusOK)
	case errors.Is(err, store.ErrDuplicate):
		// Idempotent replay: already committed. 200 without re-append.
		w.WriteHeader(http.StatusOK)
	case errors.Is(err, store.ErrSequenceRegressed):
		http.Error(w, "sequence not monotonic", http.StatusConflict)
	default:
		// Durable commit failed (e.g. fsync fault): NO 200. The source must not
		// treat the event as committed (INV-4).
		http.Error(w, "durable commit failed", http.StatusServiceUnavailable)
	}
}

// selfEmitSaturation authors a saturation event on the pipeline's own channel
// naming the saturated source. It runs on the shaped request's goroutine but
// out of the admission path (the shaped event itself was not admitted). A
// failure to self-emit is swallowed: the operator-visible over-share counter
// still records the saturation, and a self-emit fault must not turn a shaped
// (retryable) request into a hard error.
//
// The saturation PAYLOAD schema is Open-Q #5 — OCSF v1.x ships no saturation
// class — so the record carries a stable action and names the source, but
// asserts no OCSF class_uid. Resource holds the saturated source; the payload
// carries the source and its running over-share count for the operator.
func (s *Server) selfEmitSaturation(source string) {
	s.selfEmitMu.Lock()
	s.selfEmitSeq++
	seq := s.selfEmitSeq
	s.selfEmitMu.Unlock()

	payload, err := json.Marshal(map[string]any{
		"saturated_source": source,
		"over_share":       s.limiter.OverShare(source),
	})
	if err != nil {
		return
	}
	env := &ocsf.PublishEnvelope{
		ActorID:  selfEmitSource,
		Resource: source,
		Action:   saturationAction,
		Outcome:  ocsf.OutcomeSuccess,
		Sequence: seq,
		Payload:  payload,
	}
	// Host-authored by the pipeline: the source label is the pipeline's own
	// channel, never a wire peer (INV-1).
	_, _ = s.store.Admit(selfEmitSource, env)
}

const hexdigits = "0123456789abcdef"

func hexEncode(b []byte) string {
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexdigits[c>>4]
		out[i*2+1] = hexdigits[c&0x0f]
	}
	return string(out)
}

// ServerTLSConfig returns a tls.Config for the ingest server that requires and
// verifies a client certificate against clientCAs so only known peers connect.
// The verified peer CN is then the host-attested OCSF source (INV-1).
func ServerTLSConfig(serverCert tls.Certificate, clientCAs *x509.CertPool) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		MinVersion:   tls.VersionTLS13,
	}
}
