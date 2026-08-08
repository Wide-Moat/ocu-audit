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
	"errors"
	"flag"
	"fmt"
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

// main is a thin shell: every exit path funnels through run so the deferred WAL
// close actually runs. log.Fatalf skips defers, and on this component the
// skipped defer is the durable bus -- an exit that bypasses it can drop records
// the chain has already sequenced.
func main() {
	if err := run(); err != nil {
		log.Fatalf("ocu-audit: %v", err)
	}
}

func run() error {
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
		fairnessBurst = flag.Int("fairness-burst", 256, "per-source ingest burst capacity (NFR-SEC-56); a source may admit this many events back-to-back before refill governs its rate")
		fairnessRefil = flag.Duration("fairness-refill", 10*time.Millisecond, "per-source ingest refill interval (NFR-SEC-56): one token restored per interval, so the steady-state share is 1/interval events per second")
	)
	flag.Parse()

	if *serverCert == "" || *serverKey == "" || *clientCAFile == "" || *signKeyFile == "" {
		return errors.New("-server-cert, -server-key, -client-ca and -sign-key are required")
	}

	w, err := wal.Open(*walPath)
	if err != nil {
		return fmt.Errorf("open wal: %w", err)
	}
	// Now that run() returns rather than log.Fatalf-ing, this defer actually
	// fires -- and a WAL close that fails means buffered records may not be on
	// stable storage, which is exactly what this component must not swallow.
	defer func() {
		if cerr := w.Close(); cerr != nil {
			log.Printf("ocu-audit: wal close: %v", cerr)
		}
	}()

	st := store.New(w, store.SystemClock{})
	sgn, err := signer.LoadPrivateKey(*signKeyFile)
	if err != nil {
		return fmt.Errorf("load sign key: %w", err)
	}

	cert, err := tls.LoadX509KeyPair(*serverCert, *serverKey)
	if err != nil {
		return fmt.Errorf("load server keypair: %w", err)
	}
	caPEM, err := os.ReadFile(*clientCAFile)
	if err != nil {
		return fmt.Errorf("read client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return errors.New("client CA bundle contains no certificates")
	}

	authz := ingest.DefaultAuthz(*execDriverCN)
	// Per-source ingest fairness is on by default (NFR-SEC-56): a compromised or
	// runaway source is rate-shaped, not left to flood the fan-in and dilute
	// co-tenant sources. The share is operator-tunable; a non-positive value is
	// clamped up by the limiter so fairness never silently disables itself.
	share := ingest.FairnessShare{Burst: *fairnessBurst, RefillEveryMillis: fairnessRefil.Milliseconds()}
	srv := ingest.NewServerWithFairness(st, authz, ingest.MTLSPeerVerifier{}, share, store.SystemClock{})

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
		return fmt.Errorf("serve: %w", err)
	}
	// A clean shutdown returns here, so the deferred WAL close runs before the
	// process exits -- which is the whole reason this is run() and not main().
	return nil
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
	// 0600, not 0644: the signed Merkle head is the tamper-evidence artifact
	// this component exists to produce, and a world-readable one on a shared
	// host hands every local account the chain state. The WAL beside it already
	// opens 0600; this was the odd file out.
	return os.WriteFile(out, b, 0o600)
}
