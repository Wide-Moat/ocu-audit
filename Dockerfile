# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Multi-stage build for the ocu-audit fan-in service (component-07). The builder
# cross-compiles a static binary with the release flags (CGO_ENABLED=0,
# -trimpath, -s -w) so the container binary and a released binary are
# build-identical. The final stage is distroless static running as nonroot: no
# shell, no package manager, no libc - the daemon and the verifier are the only
# things in the image.
#
# Both base images are pinned by digest; bumping a base is an explicit,
# reviewable diff.

# --- builder: runs on the build host's native platform and cross-compiles.
FROM --platform=$BUILDPLATFORM golang:1.26.4@sha256:87a41d2539e5671777734e91f467499ed5eafb1fb1f77221dff2744db7a51775 AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/ocu-audit ./cmd/ocu-audit
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/ocu-audit-verify ./cmd/ocu-audit-verify

# --- final: distroless static, nonroot (uid 65532), digest-pinned.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:d093aa3e30dbadd3efe1310db061a14da60299baff8450a17fe0ccc514a16639
COPY --from=build /out/ocu-audit /usr/local/bin/ocu-audit
COPY --from=build /out/ocu-audit-verify /usr/local/bin/ocu-audit-verify
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/ocu-audit"]
