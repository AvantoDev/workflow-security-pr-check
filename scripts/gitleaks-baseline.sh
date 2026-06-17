#!/usr/bin/env bash
#
# gitleaks-baseline.sh — one-time, full-history secret scan across all org repos.
#
# The PR gate (pr-security.yml) only scans secrets introduced by each PR
# (base..head) for speed. This script catches LEGACY secrets already committed
# in history, which the diff-scoped gate will not re-flag. Run it locally,
# periodically, or after onboarding the gate.
#
# Requirements: gh (authenticated), git, docker, jq.
#
# Usage:
#   ./gitleaks-baseline.sh [ORG] [OUTPUT_DIR]
#   ORG          GitHub org/owner to scan (default: AvantoDev)
#   OUTPUT_DIR   Where to write reports     (default: ./gitleaks-baseline)
#
# Env:
#   CONCURRENCY  Parallel repos to scan (default: 4)
#   GITLEAKS_IMAGE  Override scanner image (default: ghcr.io/gitleaks/gitleaks:v8.21.2)
#   INCLUDE_ARCHIVED  Set to 1 to also scan archived repos (default: skip)
#
# Output:
#   OUTPUT_DIR/repos.txt          list of repos scanned
#   OUTPUT_DIR/<repo>.json        gitleaks JSON report (only if findings)
#   OUTPUT_DIR/SUMMARY.txt        repos with findings + counts
#
set -uo pipefail

ORG="${1:-AvantoDev}"
OUT="${2:-./gitleaks-baseline}"
CONCURRENCY="${CONCURRENCY:-4}"
GITLEAKS_IMAGE="${GITLEAKS_IMAGE:-ghcr.io/gitleaks/gitleaks:v8.21.2}"
INCLUDE_ARCHIVED="${INCLUDE_ARCHIVED:-0}"

for bin in gh git docker jq; do
  command -v "$bin" >/dev/null 2>&1 || { echo "ERROR: '$bin' is required but not found." >&2; exit 1; }
done

mkdir -p "$OUT"
SUMMARY="$OUT/SUMMARY.txt"
: > "$SUMMARY"

echo "Listing repositories in '$ORG'..."
if [ "$INCLUDE_ARCHIVED" = "1" ]; then
  gh repo list "$ORG" --limit 1000 --json nameWithOwner -q '.[].nameWithOwner' > "$OUT/repos.txt"
else
  gh repo list "$ORG" --limit 1000 --json nameWithOwner,isArchived \
    -q '.[] | select(.isArchived | not) | .nameWithOwner' > "$OUT/repos.txt"
fi
total=$(wc -l < "$OUT/repos.txt" | tr -d ' ')
echo "Found $total repo(s). Scanning with $CONCURRENCY in parallel..."

# Pre-pull the image once so parallel workers don't race on the pull.
docker pull -q "$GITLEAKS_IMAGE" >/dev/null

scan_repo() {
  local repo="$1"
  local name="${repo#*/}"
  local tmp report count
  tmp="$(mktemp -d)"
  # gh clone uses the authenticated token (works for private repos).
  if ! gh repo clone "$repo" "$tmp" -- --quiet 2>/dev/null; then
    echo "WARN: clone failed: $repo" >&2
    rm -rf "$tmp"
    return
  fi
  report="$tmp/gitleaks-report.json"
  # --exit-code 0 so a finding doesn't abort; full history is the default.
  docker run --rm -v "$tmp:/repo" "$GITLEAKS_IMAGE" \
    detect --source=/repo --redact \
    --report-format json --report-path /repo/gitleaks-report.json \
    --exit-code 0 >/dev/null 2>&1 || true
  if [ -s "$report" ]; then
    count="$(jq 'length' "$report" 2>/dev/null || echo 0)"
    if [ "${count:-0}" -gt 0 ]; then
      cp "$report" "$OUT/${name}.json"
      printf '%-50s %s finding(s)\n' "$repo" "$count" >> "$SUMMARY"
      echo "  [FINDINGS] $repo: $count"
    fi
  fi
  rm -rf "$tmp"
}
export -f scan_repo
export OUT GITLEAKS_IMAGE SUMMARY

# Fan out across repos. xargs -P controls concurrency.
xargs -a "$OUT/repos.txt" -P "$CONCURRENCY" -I {} bash -c 'scan_repo "$@"' _ {}

echo
echo "===================== BASELINE COMPLETE ====================="
if [ -s "$SUMMARY" ]; then
  echo "Repos with secrets in history (reports in $OUT/):"
  sort "$SUMMARY"
  echo
  echo "Total repos with findings: $(wc -l < "$SUMMARY" | tr -d ' ') / $total"
  echo "Review each report, rotate exposed credentials, and purge from history"
  echo "(git filter-repo / BFG) where appropriate."
else
  echo "No secrets found in history across $total repo(s). 🎉"
fi
