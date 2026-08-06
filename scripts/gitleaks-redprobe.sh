#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Red-probe the secrets gate: prove the gitleaks context actually reddens on a
# planted credential, and is clean on the tree as committed.
#
# A gate nobody proves fires is indistinguishable from a gate that matches
# nothing: both report green. This probe tells those apart by planting a
# credential and requiring the scan to redden, then requiring it to pass once
# the plant is gone.
#
# Note on scope: the job runs the container with no -w, so gitleaks never
# auto-discovers the repo's .gitleaks.toml — it scans with the built-in ruleset,
# which the step name ("default ruleset") states outright. The probe therefore
# measures the ruleset the job actually applies, not the config file sitting
# beside it. If the job ever gains --config, this probe keeps measuring
# whatever it runs, because the invocation is derived from the workflow.
#
# It runs INLINE in the secrets-gitleaks job rather than as its own workflow, so
# it rides a context that is already required: a red probe is a blocked merge
# with no branch-protection edit and no second context to keep in sync.
set -euo pipefail

# The scanner invocation is DERIVED from security.yml rather than restated here.
# A hand-copied invocation drifts from the gate it claims to measure — a probe
# pinned to one image while the job runs another reports on a scanner no PR ever
# uses. Pulling the pin out of the workflow keeps the two in lockstep by
# construction.
readonly WORKFLOW=".github/workflows/security.yml"
if [ ! -f "$WORKFLOW" ]; then
  echo "::error::$WORKFLOW not found; the probe cannot derive the scanner it must measure (fail-closed)"
  exit 1
fi

image=$(grep -oE 'zricethezav/gitleaks:v[0-9]+\.[0-9]+\.[0-9]+' "$WORKFLOW" | head -1)
if [ -z "$image" ]; then
  echo "::error::no pinned zricethezav/gitleaks:vX.Y.Z image found in $WORKFLOW — the job moved to a different scanner or an unpinned tag, and this probe has not been checked against it (fail-closed)"
  exit 1
fi

# The ARGUMENTS are derived too, not just the image. Pinning the image while
# hardcoding the flags leaves the probe measuring a scan the job does not run:
# point the job at a path that does not exist and it stops scanning anything,
# while a probe with its own --source keeps reporting a healthy gate.
args=$(grep -oE 'detect --source=[^ ]+( --[a-z-]+)*' "$WORKFLOW" | head -1)
if [ -z "$args" ]; then
  echo "::error::no 'detect --source=...' invocation found in $WORKFLOW — the job's scan arguments changed shape and this probe has not been checked against them (fail-closed)"
  exit 1
fi
# shellcheck disable=SC2206 # deliberate word-splitting: the derived flags are a
# fixed set of literals from the workflow, not user input.
readonly scan_args=($args)
echo "probe derives the scan from $WORKFLOW: $image ${scan_args[*]}"

# The job scans COMMITS (`detect --source=/repo` with no --no-git), so a planted
# working-tree file is invisible to it — probing with one would report a green
# gate that had simply looked elsewhere. The probe therefore commits the planted
# value to a scratch branch and scans that, which is the path a real leak takes.
probe_file=".gitleaks-redprobe.tmp.toml"
start_ref=$(git rev-parse --abbrev-ref HEAD)
readonly start_ref
cleanup() {
  rm -f "$probe_file"
  git rev-parse --verify -q redprobe-scratch >/dev/null 2>&1 || return 0
  git checkout -q "$start_ref" 2>/dev/null || true
  git branch -q -D redprobe-scratch 2>/dev/null || true
}
trap cleanup EXIT

# Assembled at runtime from parts so the literal never appears in the tree. A
# committed probe value is exactly what an allowlist entry (or a scanner's own
# example-secret exclusion) would neutralise — the probe would then pass while
# proving nothing, which is the failure mode it exists to catch.
planted="glpat-$(printf 'PROBE')onlyFAKE0987654321"
git checkout -q -b redprobe-scratch
printf 'gitlab_pat = "%s"\n' "$planted" >"$probe_file"
git add "$probe_file"
git -c user.email=redprobe@localhost -c user.name=redprobe commit -q -m "probe: planted credential (scratch branch, never pushed)"

# (1) PLANTED: the scan MUST report a leak. The status is captured rather than
# left to `set -e`, because a non-zero exit is the expected outcome here.
if docker run --rm -v "$PWD:/repo" "$image" "${scan_args[@]}" >/dev/null 2>&1; then
  echo "::error::gitleaks reported NO leak on a planted GitLab PAT — the secrets gate is not detecting credentials. Check the image pin and the detect arguments in .github/workflows/security.yml; a scanner that finds a planted PAT nowhere finds a real one nowhere."
  exit 1
fi
echo "ok: gate is RED on a planted secret"

# (2) CLEAN: back on the real branch the same scan must pass. Without this arm a
# scanner that failed on everything would satisfy arm (1) and look healthy.
cleanup
trap - EXIT
if ! docker run --rm -v "$PWD:/repo" "$image" "${scan_args[@]}" >/dev/null 2>&1; then
  echo "::error::gitleaks did not pass on the clean tree. Either a real secret is committed, the probe branch was not cleaned up, or the scan derived from $WORKFLOW is broken (a --source path that does not exist, or an image pin whose entrypoint differs) — check the derived invocation printed above."
  exit 1
fi
echo "ok: gate is clean on the tree as committed"

echo "gitleaks-redprobe: the gate fires RED on a planted secret and green on a clean tree"
