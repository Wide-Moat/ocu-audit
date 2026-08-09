#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Drift guard for the vendored audit fan-in contract.
#
# contracts/audit/audit-fanin.asyncapi.yaml is a byte copy of the canon contract
# (open-computer-use contracts/audit/audit-fanin.asyncapi.yaml). It was found
# stale once — a canon change landed, nobody re-vendored, and the local copy and
# the decoder stayed internally consistent while describing an old contract. The
# INV-8 conformance test catches a decoder/copy mismatch; it cannot see the copy
# diverging from CANON. This does.
#
# The pin is the canon blob OID recorded below. Two checks:
#   1. Local integrity (always): the vendored file hashes to the pin. Catches an
#      accidental local edit to the vendored copy.
#   2. Canon identity (when a canon checkout is reachable): the pin equals the
#      blob at the canon commit. Where no sibling checkout exists (a dev machine,
#      a fork), this half skips with a notice rather than failing — the pin is
#      still enforced against the local file.
#
# Bumping the contract: re-vendor from canon, then update PINNED_CANON_BLOB to
# the new `git rev-parse <canon-ref>:contracts/audit/audit-fanin.asyncapi.yaml`.
# A deliberate two-line change, never a silent drift.
set -euo pipefail

cd "$(dirname "$0")/.."

readonly VENDORED="contracts/audit/audit-fanin.asyncapi.yaml"

# The canon blob OID the vendored copy must equal. Canon: open-computer-use
# next/v1, contracts/audit/audit-fanin.asyncapi.yaml, version 1.2.0.
readonly PINNED_CANON_BLOB="bb56a7c6ba7300243ad46dc35ff2ec47f7c5f366"

# The canon commit the identity half reads the pinned blob at, so the check is
# immune to whichever branch the sibling checkout has out.
readonly CANON_COMMIT="0a5921cdfb090c95f67549eae0bd98fe05a9f23e"

readonly CANON_DIR="${OCU_CANON_DIR:-../open-computer-use}"

if [ ! -f "$VENDORED" ]; then
  echo "::error::vendored contract $VENDORED is missing"
  exit 1
fi

# 1. Local integrity: the file must hash to the pin.
local_blob=$(git hash-object "$VENDORED")
if [ "$local_blob" != "$PINNED_CANON_BLOB" ]; then
  echo "::error::vendored $VENDORED hashes to $local_blob, not the pinned canon blob $PINNED_CANON_BLOB"
  echo "::error::re-vendor from canon and update PINNED_CANON_BLOB, or revert the local edit"
  exit 1
fi

# 2. Canon identity: only when a canon checkout is reachable.
if [ ! -e "$CANON_DIR" ]; then
  if [ -n "${OCU_CANON_DIR:-}" ]; then
    echo "::error::OCU_CANON_DIR is set but $CANON_DIR does not exist"
    exit 1
  fi
  echo "::notice::canon checkout not present ($CANON_DIR); local pin enforced, canon identity skipped"
  echo "vendored contract ok: matches pin $PINNED_CANON_BLOB (canon identity skipped)"
  exit 0
fi

if ! git -C "$CANON_DIR" rev-parse --git-dir >/dev/null 2>&1; then
  echo "::error::$CANON_DIR exists but is not a git checkout; cannot verify canon identity"
  exit 1
fi

if ! git -C "$CANON_DIR" cat-file -e "${CANON_COMMIT}^{commit}" 2>/dev/null; then
  echo "::error::canon checkout $CANON_DIR lacks pinned commit $CANON_COMMIT -- fetch the canon next/v1 line"
  exit 1
fi

# Canon vendors the contract at the SAME path as this repo (contracts/audit/...).
canon_blob=$(git -C "$CANON_DIR" rev-parse "${CANON_COMMIT}:${VENDORED}")
if [ "$canon_blob" != "$PINNED_CANON_BLOB" ]; then
  echo "::error::the pin $PINNED_CANON_BLOB does not match the canon blob $canon_blob at $CANON_COMMIT"
  echo "::error::canon moved; re-vendor and bump both PINNED_CANON_BLOB and CANON_COMMIT"
  exit 1
fi

echo "vendored contract ok: matches pin $PINNED_CANON_BLOB and canon at $CANON_COMMIT"
