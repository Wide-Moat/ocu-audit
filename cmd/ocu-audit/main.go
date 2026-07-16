// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Command ocu-audit is the central audit fan-in service (component-07). It
// terminates the per-source mTLS ingest face, host-attests each source from its
// verified client certificate, enforces per-source monotonic sequence with
// replay dedupe, authors the per-source hash chain, durably commits every
// admitted event to the append-only WAL before acknowledging (fsync-then-ack,
// INV-4), maintains the daily Merkle accumulator, and signs the daily-head
// submission envelope with a host-local Ed25519 key.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Wide-Moat/ocu-audit/internal/ingest"
	"github.com/Wide-Moat/ocu-audit/internal/signer"
	"github.com/Wide-Moat/ocu-audit/internal/store"
	"github.com/Wide-Moat/ocu-audit/internal/wal"
)

func main() {
	var (
		listen        = flag.String("listen", ":8443", "mTLS ingest listen address")
		walPath       = flag.String("wal", "audit.wal", "append-only WAL path (durable bus)")
		serverCert    = flag.String("server-cert", "", "server certificate PEM")
		serverKey     = flag.String("server-key", "", "server private key PEM")
		clientCAFile  = flag.String("client-ca", "", "client CA bundle PEM for mTLS peer verification")
		signKeyFile   = flag.String("sign-key", "", "Ed25519 private key (64 raw bytes) for head envelope")
		execDriverCN  = flag.String("control-exec-driver-cn", "control-plane", "peer CN authorized to host-author the session-sandbox channel (NFR-SEC-47)")
		headDumpEvery = flag.Duration("head-interval", 24*time.Hour, "daily head cadence")
		headOut       = flag.String("head-out", "audit-head.json", "signed daily-head output path")
	)
	flag.Parse()

	if *serverCert == "" || *serverKey == "" || *clientCAFile == "" || *signKeyFile == "" {
		log.Fatal("ocu-audit: -server-cert, -server-key, -client-ca and -sign-key are required")
	}

	w, err := wal.Open(*walPath)
	if err != nil {
		log.Fatalf("ocu-audit: open wal: %v", err)
	}
	defer w.Close()

	st := store.New(w)
	sgn, err := signer.LoadPrivateKey(*signKeyFile)
	if err != nil {
		log.Fatalf("ocu-audit: load sign key: %v", err)
	}

	cert, err := tls.LoadX509KeyPair(*serverCert, *serverKey)
	if err != nil {
		log.Fatalf("ocu-audit: load server keypair: %v", err)
	}
	caPEM, err := os.ReadFile(*clientCAFile)
	if err != nil {
		log.Fatalf("ocu-audit: read client CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		log.Fatalf("ocu-audit: client CA bundle contains no certificates")
	}

	authz := ingest.DefaultAuthz(*execDriverCN)
	srv := ingest.NewServer(st, authz, ingest.MTLSPeerVerifier{})

	httpSrv := &http.Server{
		Addr:              *listen,
		Handler:           srv.Handler(),
		TLSConfig:         ingest.ServerTLSConfig(cert, pool),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Daily head cadence: sign the head and write the submission envelope.
	go func() {
		t := time.NewTicker(*headDumpEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := dumpHead(st, sgn, *headOut); err != nil {
					log.Printf("ocu-audit: head dump: %v", err)
				}
			}
		}
	}()

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutCtx)
	}()

	log.Printf("ocu-audit: mTLS ingest listening on %s (wal=%s)", *listen, *walPath)
	if err := httpSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		log.Fatalf("ocu-audit: serve: %v", err)
	}
}

// dumpHead signs the current Merkle head and writes the submission envelope.
func dumpHead(st *store.Store, sgn *signer.Signer, out string) error {
	head, size, err := st.Head()
	if err != nil {
		return err
	}
	env := signer.HeadEnvelope{
		Date:     time.Now().UTC().Format("2006-01-02"),
		TreeSize: size,
		Head:     head,
	}
	sh := sgn.Sign(env)
	b, err := json.MarshalIndent(sh, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(out, b, 0o644)
}
