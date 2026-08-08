// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Command ocu-audit-edgetail bridges the egress edge's Envoy JSON access log
// to the audit fan-in (A6, component-06 P6-R1: one OCSF event per
// connection). The edge stays stock Envoy — configuration writes the JSON
// log; this host-side, pipeline-family collector converts each line to an
// OCSF 4002 publish on the egress-edge channel over mTLS, resuming across
// restarts from a durable cursor without regressing its sequence.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Wide-Moat/ocu-audit/internal/edgetail"
	"github.com/Wide-Moat/ocu-audit/internal/ocsf"
	"github.com/Wide-Moat/ocu-audit/pkg/publish"
)

// version is stamped by the release build (-X main.version); "dev" identifies
// a non-release build in the -version output.
var version = "dev"

func main() {
	if err := run(); err != nil {
		log.Fatalf("ocu-audit-edgetail: %v", err)
	}
}

func run() error {
	var (
		logPath     = flag.String("log", "edge-access.log", "Envoy JSON access-log path to tail")
		cursorPath  = flag.String("cursor", "edgetail-cursor.json", "durable {offset, sequence} cursor path")
		faninURL    = flag.String("fanin-url", "", "audit fan-in base URL (required)")
		clientCert  = flag.String("client-cert", "", "mTLS client certificate PEM for the egress-edge channel (required)")
		clientKey   = flag.String("client-key", "", "mTLS client key PEM (required)")
		caFile      = flag.String("ca", "", "fan-in server CA bundle PEM (required)")
		tick        = flag.Duration("tick", 5*time.Second, "tail interval")
		showVersion = flag.Bool("version", false, "print the build version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return nil
	}
	if *faninURL == "" || *clientCert == "" || *clientKey == "" || *caFile == "" {
		return fmt.Errorf("-fanin-url, -client-cert, -client-key and -ca are required")
	}

	cert, err := tls.LoadX509KeyPair(*clientCert, *clientKey)
	if err != nil {
		return fmt.Errorf("load client keypair: %w", err)
	}
	caPEM, err := os.ReadFile(*caFile) // #nosec G304 -- operator's -ca flag
	if err != nil {
		return fmt.Errorf("read CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return fmt.Errorf("CA bundle contains no certificates")
	}
	client, err := publish.New(publish.Config{
		BaseURL: *faninURL,
		Channel: "audit.ingest.egress-edge",
		TLS: &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      pool,
			MinVersion:   tls.VersionTLS13,
		},
	})
	if err != nil {
		return err
	}

	tailer := edgetail.NewTailer(*logPath, *cursorPath, clientAdapter{client})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Printf("ocu-audit-edgetail: tailing %s -> %s (tick %v)", *logPath, *faninURL, *tick)
	t := time.NewTicker(*tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			tailer.RunOnce(ctx)
		}
	}
}

// clientAdapter maps the tailer's envelope to the wire client's. The two
// shapes are field-identical by contract; the adapter keeps the internal
// package free of the public client type.
type clientAdapter struct {
	c *publish.Client
}

func (a clientAdapter) Publish(ctx context.Context, env *ocsf.PublishEnvelope) error {
	return a.c.Publish(ctx, publish.Envelope{
		TraceID:   env.TraceID,
		SessionID: env.SessionID,
		ActorID:   env.ActorID,
		Resource:  env.Resource,
		Action:    env.Action,
		Outcome:   publish.Outcome(env.Outcome),
		Sequence:  env.Sequence,
		Payload:   env.Payload,
	})
}
