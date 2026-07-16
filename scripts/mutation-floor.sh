#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Armed mutation floor for the highest-stakes crypto guard package: the
# per-source hash chain and its verifier (internal/chain). This is the site
# where a live-but-unasserted mutant is most dangerous - a chain that stops
# linking, a Compute that stops depending on prev/seq/event, a verifier that
# stops rejecting a broken link. go-mutesting resolves packages via `go list`
# and kills on real test PASS/FAIL, so its score is stable and armable (unlike
# go-gremlins, whose timeout calibration flakes on the rapid property suites).
# The known-answer tests (internal/chain/kat_test.go) are what let a symmetric
# Compute mutant be killed rather than surviving because Author and Verify agree
# with the mutated code.
#
# Scope note: internal/ocsf and internal/signer carry their own strengthened
# unit + KAT suites but are advisory (gremlins scope in mutation.yml), not
# armed, this round - their surviving mutants are error-branch and non-crypto
# bookkeeping, not the chain-linkage guard. Ratchet: extend the armed floor to
# the canonical-encoding guard and the signer verify path as their scores
# stabilise; raise FLOOR toward the canon 0.60+ floor.
#
# A score below FLOOR, or any fail-closed guard tripping (errored mutants, an
# unparsable summary), fails the job.
set -euo pipefail

# Per-package armed floors, each set below its measured local baseline with
# headroom so a real regression reds while measurement noise does not.
# - internal/chain: measured 0.77 (17/22 killed) with the known-answer +
#   input-sensitivity tests; floor 0.70.
# - internal/store: measured 0.64 (47/73 killed) with the restart-recovery
#   suite (recover_test.go) added; floor 0.55. Every recovery GUARD mutant
#   (skip chain verification, skip a state-map rebuild, skip the record list,
#   mis-order the leaves) is killed; the survivors are the unreachable
#   AppendLeaf error branch, one equivalent mutant, and pre-existing
#   error-branch bookkeeping outside the recovery path.
# MUTATION_FLOOR overrides every per-package floor when set (CI knob).
PACKAGES_WITH_FLOORS=(
  "github.com/Wide-Moat/ocu-audit/internal/chain:0.70"
  "github.com/Wide-Moat/ocu-audit/internal/store:0.55"
)

# Per-mutant hard timeout so a hanging mutant is killed, not run to the job cap.
export MUTATE_TIMEOUT="${MUTATE_TIMEOUT:-60}"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

for entry in "${PACKAGES_WITH_FLOORS[@]}"; do
  pkg="${entry%:*}"
  floor="${MUTATION_FLOOR:-${entry##*:}}"

  rc=0
  go-mutesting "$pkg" >"$tmp" 2>&1 || rc=$?

  cat "$tmp"

  # Fail-closed: an errored run (tool crash, compile failure) is never a pass.
  if [ "$rc" -ne 0 ] && ! grep -qE '^The mutation score is' "$tmp"; then
    echo "::error::go-mutesting errored (rc=$rc) on $pkg without emitting a score; failing closed"
    exit 1
  fi

  score="$(grep -oE 'The mutation score is [0-9.]+' "$tmp" | grep -oE '[0-9.]+' | tail -1 || true)"
  if [ -z "$score" ]; then
    echo "::error::could not parse a mutation score for $pkg from go-mutesting output; failing closed"
    exit 1
  fi

  echo "mutation score for $pkg: $score (floor $floor)"
  awk -v s="$score" -v f="$floor" 'BEGIN { exit !(s+0 >= f+0) }' || {
    echo "::error::mutation score $score for $pkg is below the floor $floor"
    exit 1
  }
done
echo "mutation floor OK"
