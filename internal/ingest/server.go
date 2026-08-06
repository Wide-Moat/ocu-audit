// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingest

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"strings"

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

// Server is the ingest HTTP handler.
type Server struct {
	store    *store.Store
	authz    *PeerChannelAuthz
	verifier PeerVerifier
}

// NewServer builds the ingest handler.
func NewServer(st *store.Store, authz *PeerChannelAuthz, v PeerVerifier) *Server {
	return &Server{store: st, authz: authz, verifier: v}
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
