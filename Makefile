# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors

.PHONY: all build test race lint fmt vet staticcheck mutation verify-fixture clean

GO ?= go

all: build test

build:
	$(GO) build ./...
	$(GO) build -o ocu-audit ./cmd/ocu-audit
	$(GO) build -o ocu-audit-verify ./cmd/ocu-audit-verify

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

fmt:
	gofmt -l -w .

vet:
	$(GO) vet ./...

staticcheck:
	$(GO) run honnef.co/go/tools/cmd/staticcheck@2025.1.1 ./...

lint:
	golangci-lint run --timeout=5m

# Armed mutation floor over the hash-chain guard (internal/chain).
mutation:
	bash scripts/mutation-floor.sh

clean:
	rm -f ocu-audit ocu-audit-verify cover.out
