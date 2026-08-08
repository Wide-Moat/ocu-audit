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
	"path/filepath"
	"syscall"
	"time"

	"github.com/Wide-Moat/ocu-audit/internal/fanout"
	"github.com/Wide-Moat/ocu-audit/internal/ingest"
	"github.com/Wide-Moat/ocu-audit/internal/retention"
	"github.com/Wide-Moat/ocu-audit/internal/signer"
	"github.com/Wide-Moat/ocu-audit/internal/store"
)

// version is stamped by the release build (-X main.version); "dev" identifies a
// non-release build in the -version output.
var version = "dev"

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
		coldDir       = flag.String("cold-dir", "", "cold-tier directory (ADR-0045; the customer's WORM mount point); empty derives <dir of -wal>/cold")
		retFloor      = flag.Int("retention-floor-years", 7, "retention floor in years (NFR-COMP-01, >= 7); a shrink against the pinned checkpoint refuses boot")
		retHotMax     = flag.Duration("retention-hot-max", 2160*time.Hour, "hot-tier ceiling (NFR-COMP-01, <= 90 d)")
		retSeal       = flag.Duration("retention-seal-interval", 24*time.Hour, "seal cadence for the active WAL file")
		retCheckpoint = flag.String("retention-checkpoint", "", "signed retention-checkpoint path; empty derives <dir of -wal>/retention-checkpoint.json")
		retTick       = flag.Duration("retention-tick", time.Hour, "retention manager tick interval")
		fanoutSink    = flag.String("fanout-sink", "", "SIEM-bridge sink file (JSON lines; the ADR-0009 opt-in bridge). Empty = no fan-out; the hash-chained WAL stays the authoritative record either way")
		fanoutTick    = flag.Duration("fanout-tick", 10*time.Second, "fan-out pump tick interval")
		showVersion   = flag.Bool("version", false, "print the build version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return nil
	}

	if *serverCert == "" || *serverKey == "" || *clientCAFile == "" || *signKeyFile == "" {
		return errors.New("-server-cert, -server-key, -client-ca and -sign-key are required")
	}

	sgn, err := signer.LoadPrivateKey(*signKeyFile)
	if err != nil {
		return fmt.Errorf("load sign key: %w", err)
	}

	// Retention (ADR-0045, NFR-COMP-01): an invalid policy or a checkpoint
	// that fails its signature, floor, or shrink gate refuses boot.
	policy, err := retention.NewPolicy(*retFloor, *retHotMax, *retSeal)
	if err != nil {
		return err
	}
	hotDir := filepath.Dir(*walPath)
	cold := *coldDir
	if cold == "" {
		cold = filepath.Join(hotDir, "cold")
	}
	if err := os.MkdirAll(cold, 0o700); err != nil {
		return fmt.Errorf("cold dir: %w", err)
	}
	cpPath := *retCheckpoint
	if cpPath == "" {
		cpPath = filepath.Join(hotDir, "retention-checkpoint.json")
	}
	// The manager's seams close over st and srv, which exist only after
	// recovery; the manager never ticks before both are assigned.
	var st *store.Store
	var srv *ingest.Server
	mgr, err := retention.NewManager(retention.ManagerConfig{
		Policy:         policy,
		HotDir:         hotDir,
		ColdDir:        cold,
		CheckpointPath: cpPath,
		Signer:         sgn,
		CurrentCount:   func() uint64 { return st.GlobalCount() },
		Seal:           func(p string) (store.SealSnapshot, error) { return st.SealActive(p) },
		Emit: func(action, resource string, payload map[string]any) {
			srv.SelfEmit(action, resource, payload)
		},
	})
	if err != nil {
		return fmt.Errorf("retention checkpoint: %w", err)
	}

	// Recover, never merely open: the store rebuilds chain tips, sequence
	// tips, dedupe, and the Merkle accumulator, verifying every chain link
	// before serving. With a rotated prefix the boot is HOT-ONLY, anchored on
	// the signed checkpoint — the cold seam is never read at boot (ADR-0045),
	// so a cold-mount outage cannot take the audit plane down.
	cp := mgr.Checkpoint()
	if cp.HasAnchors() {
		st, err = store.RecoverAnchored(*walPath, store.SystemClock{}, cp.BootAnchor())
	} else {
		st, err = store.Recover(*walPath, store.SystemClock{})
	}
	if err != nil {
		return fmt.Errorf("recover wal: %w", err)
	}
	// A store close that fails means buffered records may not be on stable
	// storage, which is exactly what this component must not swallow.
	defer func() {
		if cerr := st.Close(); cerr != nil {
			log.Printf("ocu-audit: store close: %v", cerr)
		}
	}()
	log.Printf("ocu-audit: recovered %d committed records from %s", len(st.Records()), *walPath)

	// Sign and write a fresh head IMMEDIATELY after recovery: without this, a
	// restart leaves the previous generation's head (or a genesis head) on
	// disk for up to one ticker interval, and the independent verifier
	// correctly fails the freshness gate in that window.
	if err := dumpHead(st, sgn, *headOut); err != nil {
		return fmt.Errorf("initial head dump: %w", err)
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
	srv = ingest.NewServerWithFairness(st, authz, ingest.MTLSPeerVerifier{}, share, store.SystemClock{})

	// NFR-SEC-45: an accepted retention-policy change (necessarily a
	// non-shrink) self-emits a chain-linked record and repins the checkpoint.
	if err := mgr.BootPolicySync(); err != nil {
		return fmt.Errorf("retention policy sync: %w", err)
	}

	httpSrv := &http.Server{
		Addr:              *listen,
		Handler:           srv.Handler(),
		TLSConfig:         ingest.ServerTLSConfig(cert, pool),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Opt-in SIEM-side fan-out (component-07 P7-D1): decoupled from admission,
	// resumed across restarts by a durable cursor, at-least-once; a cursor
	// lagging past the rotation boundary is counted and evidenced, never a
	// reason to stall rotation.
	if *fanoutSink != "" {
		sink, err := fanout.NewFileSink(*fanoutSink)
		if err != nil {
			return fmt.Errorf("fanout sink: %w", err)
		}
		defer func() { _ = sink.Close() }()
		pump := fanout.NewPump(st, sink, filepath.Join(hotDir, "fanout-cursor.json"), srv.SelfEmit)
		go func() {
			t := time.NewTicker(*fanoutTick)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					pump.RunOnce()
				}
			}
		}()
	}

	// Retention cadence (ADR-0045): each tick seals when due, rotates due
	// segments hot -> cold, and emits breach evidence. Failures inside a tick
	// never touch admission; they self-emit and retry next tick.
	go func() {
		t := time.NewTicker(*retTick)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				mgr.Tick(store.SystemClock{}.NowMillis())
			}
		}
	}()

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
