#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Red-probe the trufflehog half of the secrets gate: prove the scan actually
# reddens on a planted credential, and is quiet on the tree as committed.
#
# The failure this guards against is not "trufflehog is missing" — it is a gate
# that runs, finds nothing, and is read as "no secrets". A scan can go quiet
# without ever failing: one over-broad entry in an exclude file removes the
# whole tree from the scan, a `path:` input pointed at a directory that does not
# exist scans nothing, and either way the job stays green. Green from a scanner
# that looked nowhere is indistinguishable from green from a clean repo unless
# something plants a secret and checks it comes back.
#
# It runs INLINE in the secrets-trufflehog job rather than as its own workflow,
# so it rides a context that is already required: a red probe is a blocked merge
# with no branch-protection edit and no second context to keep in sync.
set -euo pipefail

# The action pin is DERIVED from security.yml rather than restated here. A probe
# that carries its own copy of the version drifts from the gate it claims to
# measure, and a probe measuring a scanner no PR ever runs proves nothing about
# the one that does. Reading the pin out of the workflow also gives the probe a
# place to fail closed when the pin moves: detector behaviour is a property of
# the scanner release, so a revision this probe has never been checked against
# is an unknown, not a pass.
readonly WORKFLOW=".github/workflows/security.yml"
if [ ! -f "$WORKFLOW" ]; then
  echo "::error::$WORKFLOW not found; the probe cannot derive the gate it must measure (fail-closed)"
  exit 1
fi

# The action SHA is the identity that actually binds — the trailing `# vX.Y.Z`
# comment is prose and can be edited without changing what runs. Match on the
# SHA and read the version comment only for the human-facing message.
readonly PINNED_SHA="f446421baf832d6356c42c1743d99abff52ff334"
actual_sha=$(grep -oE 'trufflesecurity/trufflehog@[0-9a-f]{40}' "$WORKFLOW" | head -1 | cut -d@ -f2)
if [ -z "$actual_sha" ]; then
  echo "::error::no SHA-pinned trufflesecurity/trufflehog action found in $WORKFLOW — the job moved to a different scanner or an unpinned ref, and this probe has not been checked against it (fail-closed)"
  exit 1
fi
if [ "$actual_sha" != "$PINNED_SHA" ]; then
  echo "::error::the trufflehog action pin in $WORKFLOW moved to ${actual_sha}; this probe was checked against ${PINNED_SHA}. Detector behaviour is a property of the scanner release, so a bump must be re-verified here (run this script, confirm both arms) and PINNED_SHA updated in the same commit (fail-closed)"
  exit 1
fi
echo "probe derives the gate from $WORKFLOW: trufflesecurity/trufflehog@${actual_sha}"

if ! command -v trufflehog >/dev/null 2>&1; then
  echo "::error::trufflehog not found on PATH; the secrets red-probe cannot run (fail-closed)"
  exit 1
fi

probe_file="zz_trufflehog_redprobe.txt"
report=$(mktemp)
# CI checks out a DETACHED HEAD, where `rev-parse --abbrev-ref HEAD` answers the
# literal string "HEAD" — restoring that is a no-op. Record the COMMIT, which
# restores the starting point on a branch and on a detached HEAD alike, and the
# symbolic name separately so a local run lands back on the branch it started on.
start_commit=$(git rev-parse HEAD)
start_branch=$(git rev-parse --abbrev-ref HEAD)
readonly start_commit start_branch
cleanup() {
  rm -f "$probe_file" "$report"
  # Nothing is committed by this probe, so there is no branch to unwind — but
  # restore the ref anyway, unconditionally and cheaply, so an interrupted run
  # or a future edit that does move HEAD cannot leave the caller somewhere else.
  local now
  now=$(git rev-parse HEAD 2>/dev/null || echo "")
  [ -n "$now" ] && [ "$now" = "$start_commit" ] && return 0
  if [ "$start_branch" != "HEAD" ]; then
    git checkout -q "$start_branch" 2>/dev/null || true
  else
    git checkout -q --detach "$start_commit" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# A structurally valid but entirely fake AWS key pair. It authenticates nothing;
# the scan runs with --no-verification (as the gate does), so detection is by
# shape and no network call is ever made against it.
#
# Assembled at runtime from parts so the literal never sits in the tree. A
# committed probe value is exactly what an allowlist entry — or the scanner's own
# example-secret exclusion — would neutralise: the tree scan would flag this
# script, someone would add an exclude entry to quiet it, and that entry would
# also hide the planted match. The probe would then agree with itself forever.
#
# The canonical AWS documentation pair (AKIAIOSFODNN7EXAMPLE / wJalrXUtnFEMI…KEY)
# is deliberately NOT used: scanners allowlist it as a known placeholder, so a
# probe built on it reports nothing and reads as a broken gate when the gate is
# fine. The same trap is recorded in scripts/gitleaks-redprobe.sh.
akid="AKIA$(printf 'QYLPZ4X7NBVCD2WE')"
secret="wJalrXUtnFEMIK7MDENGbPxRfi$(printf 'CYzR8h2NqLpX4T')"
{
  printf 'aws_access_key_id = %s\n' "$akid"
  printf 'aws_secret_access_key = %s\n' "$secret"
} >"$probe_file"

# The repo has no .trufflehog-exclude.txt today and the workflow passes no
# --exclude-paths. Honour one if it appears: the exclude file is the single most
# likely way this gate gets narrowed to nothing, so the probe must scan under the
# same exclusions the gate does or it would report health the gate does not have.
exclude_arg=()
if [ -f .trufflehog-exclude.txt ]; then
  exclude_arg=(--exclude-paths .trufflehog-exclude.txt)
  echo "probe honours .trufflehog-exclude.txt"
fi

# trufflehog exits non-zero only when given --fail, so an exit code says nothing
# about what was scanned. Ask for JSON and judge the CONTENT: the report must
# NAME the planted path. A count-based check is weaker than it looks — any
# pre-existing finding elsewhere in the tree would satisfy "found something"
# while the planted file went unseen, and the probe would call a blind gate healthy.
scan() {
  trufflehog filesystem . --no-verification --json "${exclude_arg[@]}" >"$report" 2>/dev/null || true
}

# (1) PLANTED: the scan MUST name the planted file.
scan
if ! grep -q "$probe_file" "$report"; then
  echo "::error::trufflehog did not report the planted credential in ${probe_file}. The secrets scan is not covering the tree — check .trufflehog-exclude.txt for an over-broad entry, and the action's path/extra_args inputs in ${WORKFLOW}. A scanner that finds a planted AWS key pair nowhere finds a real one nowhere."
  exit 1
fi
echo "ok: gate is RED on the planted credential, and names ${probe_file}"

# (2) CLEAN: with the plant removed the same scan must come back quiet. Without
# this arm a scanner that reported every file — a broken detector, a report that
# echoed its input — would satisfy arm (1) and look healthy.
rm -f "$probe_file"
scan
if grep -q "$probe_file" "$report"; then
  echo "::error::trufflehog still reports ${probe_file} after removal; the probe file was not cleaned up, or the scan is reading a stale path"
  exit 1
fi
if [ -s "$report" ]; then
  echo "::error::trufflehog reports findings on the tree as committed:"
  grep -o '"file":"[^"]*"' "$report" | sort -u
  echo "::error::either a real secret is committed, or the scan's scope changed — check ${WORKFLOW}"
  exit 1
fi
echo "ok: gate is quiet on the tree as committed"

echo "trufflehog-redprobe: the gate fires RED on a planted credential, names the planted file, and is quiet on a clean tree"
