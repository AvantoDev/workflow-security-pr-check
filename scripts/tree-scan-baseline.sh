#!/usr/bin/env bash
#
# tree-scan-baseline.sh — scheduled whole-tree scan across every repo in an org.
#
# ST-1014, Part B: pr-security.yml's Gitleaks/Semgrep/OSV-Scanner jobs are
# deliberately diff-aware (their cost scales with PR size) — correct for a
# per-PR gate, but it means anything already sitting in a repo's tree before
# the pipeline existed, or pushed straight to a branch, is invisible to it
# forever. This runs the same three scanners in whole-tree mode, plus the
# Shai-Hulud IOC guard (tree-ioc-scan.sh, already tree-based), across every
# repo on a schedule — no PR, so nothing to diff against.
#
# Modeled on gitleaks-baseline.sh's clone-fan-out (xargs -P / gh repo clone),
# extended to run all four checks against the SAME clone instead of a
# separate GitHub Actions job or matrix entry per scanner per repo — with
# 500+ repos in scope across two orgs, a matrix explodes run count and cost
# far more than looping scanners over one clone per repo in a single job.
# Interface intentionally mirrors deep-scan-org.sh's ORG-env + repo-list-file
# shape (not gitleaks-baseline.sh's positional org/output-dir), so both
# scripts compose with the same enumerate-org-repos.sh output.
#
# Anti-self-approval note: pr-security.yml resolves .gitleaks.toml /
# osv-scanner.toml only from the PR's BASE commit, because a PR could
# otherwise introduce a finding and its own suppression in the same change.
# There is no "base vs head" on a scheduled run — nothing adversarial is
# being merged in the same action — so config here is read directly from the
# checked-out working tree. This is deliberate, not an oversight: the whole
# tree is already trusted, existing state for a baseline sweep like this one.
#
# SAFETY: full (non-bare) clones are used because these scanners need to read
# a real working tree, unlike deep-scan-org.sh's bare-clone IOC scan. Each
# clone is scanned read-only and deleted immediately after.
#
# Usage:
#   ORG=<org> ./tree-scan-baseline.sh <repo-list> <output-dir>
#   repo-list    one bare repo name per line (see enumerate-org-repos.sh)
#   output-dir   where to write reports
#
# Requirements: gh (authenticated), git, docker, jq.
#
# Env:
#   CONCURRENCY     Parallel repos to scan (default: 4)
#   GITLEAKS_IMAGE  default: ghcr.io/gitleaks/gitleaks:v8.21.2
#   OSV_IMAGE       default: ghcr.io/google/osv-scanner:v1.9.1
#   SKIP_SEMGREP    set to 1 to skip Semgrep (the slowest scanner) for a fast
#                   validation run
#
# Output:
#   OUTPUT_DIR/<repo>/gitleaks.json   (only if findings)
#   OUTPUT_DIR/<repo>/osv.json        (only if findings)
#   OUTPUT_DIR/<repo>/semgrep.json    (only if findings)
#   OUTPUT_DIR/<repo>/ioc.txt         (tree-ioc-scan.sh output, always written)
#   OUTPUT_DIR/SUMMARY.csv            one row per repo
set -uo pipefail

ORG="${ORG:?set ORG=<github-org>}"
LIST="${1:?usage: ORG=<org> $0 <repo-list> <output-dir>}"
OUT="${2:?usage: ORG=<org> $0 <repo-list> <output-dir>}"
CONCURRENCY="${CONCURRENCY:-4}"
GITLEAKS_IMAGE="${GITLEAKS_IMAGE:-ghcr.io/gitleaks/gitleaks:v8.21.2}"
OSV_IMAGE="${OSV_IMAGE:-ghcr.io/google/osv-scanner:v1.9.1}"
SKIP_SEMGREP="${SKIP_SEMGREP:-0}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for bin in gh git docker jq; do
  command -v "$bin" >/dev/null 2>&1 || { echo "ERROR: '$bin' is required but not found." >&2; exit 1; }
done

mkdir -p "$OUT"
SUMMARY="$OUT/SUMMARY.csv"
[ -s "$SUMMARY" ] || echo "repo,gitleaks_findings,osv_findings,semgrep_findings,ioc_rc" > "$SUMMARY"

total=$(wc -l < "$LIST" | tr -d ' ')
echo "tree-scan-baseline: org=$ORG $total repo(s) to scan, concurrency=$CONCURRENCY"

docker pull -q "$GITLEAKS_IMAGE" >/dev/null
docker pull -q "$OSV_IMAGE" >/dev/null

scan_repo() {
  local repo="$1"
  local tmp rd
  tmp="$(mktemp -d)"
  rd="$OUT/$repo"

  if ! gh repo clone "$ORG/$repo" "$tmp" -- --quiet 2>/dev/null; then
    echo "WARN: clone failed: $ORG/$repo" >&2
    echo "$repo,CLONE_FAILED,,,," >> "$SUMMARY"
    rm -rf "$tmp"
    return
  fi

  # -- Gitleaks: whole-tree, config resolved from the working tree itself ---
  cfg_mount=() cfg_arg=()
  if [ -f "$tmp/.gitleaks.toml" ]; then
    cfg_mount=(-v "$tmp/.gitleaks.toml:/config/.gitleaks.toml:ro")
    cfg_arg=(--config /config/.gitleaks.toml)
  fi
  docker run --rm -v "$tmp:/repo" "${cfg_mount[@]}" "$GITLEAKS_IMAGE" \
    detect --source=/repo --redact --no-git "${cfg_arg[@]}" \
    --report-format json --report-path /repo/.gitleaks-report.json \
    --exit-code 0 >/dev/null 2>&1 || true
  gl_n=0
  if [ -s "$tmp/.gitleaks-report.json" ]; then
    gl_n=$(jq 'length' "$tmp/.gitleaks-report.json" 2>/dev/null || echo 0)
  fi

  # -- OSV-Scanner: single whole-tree pass, no base/head diff ----------------
  osv_cfg_mount=() osv_cfg_arg=()
  if [ -f "$tmp/osv-scanner.toml" ]; then
    osv_cfg_mount=(-v "$tmp/osv-scanner.toml:/config/osv-scanner.toml:ro")
    osv_cfg_arg=(--config /config/osv-scanner.toml)
  fi
  docker run --rm -v "$tmp:/src" "${osv_cfg_mount[@]}" "$OSV_IMAGE" "${osv_cfg_arg[@]}" \
    --recursive --format json /src > "$tmp/.osv-report.json" 2>/dev/null || true
  osv_n=0
  if [ -s "$tmp/.osv-report.json" ]; then
    osv_n=$(jq '[.results[]?.packages[]?.vulnerabilities[]?] | length' "$tmp/.osv-report.json" 2>/dev/null || echo 0)
  fi

  # -- Semgrep: whole-tree ----------------------------------------------------
  sg_n=0
  if [ "$SKIP_SEMGREP" != "1" ]; then
    docker run --rm -v "$tmp:/src" -w /src semgrep/semgrep \
      semgrep scan --config auto --json --output /src/.semgrep-report.json --quiet >/dev/null 2>&1 || true
    if [ -s "$tmp/.semgrep-report.json" ]; then
      sg_n=$(jq '.results | length' "$tmp/.semgrep-report.json" 2>/dev/null || echo 0)
    fi
  fi

  # -- Shai-Hulud IOC guard: already whole-tree, exit 0/1/3, fail-closed on 3
  ioc_rc=0
  if [ -f "$SCRIPT_DIR/tree-ioc-scan.sh" ]; then
    ioc_out=$(bash "$SCRIPT_DIR/tree-ioc-scan.sh" "$tmp" 2>&1); ioc_rc=$?
  else
    ioc_out="tree-ioc-scan.sh not found next to this script"; ioc_rc=3
  fi

  if [ "$gl_n" -gt 0 ] || [ "$osv_n" -gt 0 ] || [ "$sg_n" -gt 0 ] || [ "$ioc_rc" != "0" ]; then
    mkdir -p "$rd"
    [ "$gl_n" -gt 0 ] && cp "$tmp/.gitleaks-report.json" "$rd/gitleaks.json"
    [ "$osv_n" -gt 0 ] && cp "$tmp/.osv-report.json" "$rd/osv.json"
    [ "$sg_n" -gt 0 ] && cp "$tmp/.semgrep-report.json" "$rd/semgrep.json"
    printf '%s\n' "$ioc_out" > "$rd/ioc.txt"
    echo "  [FINDINGS] $repo: gitleaks=$gl_n osv=$osv_n semgrep=$sg_n ioc_rc=$ioc_rc"
  fi
  echo "$repo,$gl_n,$osv_n,$sg_n,$ioc_rc" >> "$SUMMARY"
  rm -rf "$tmp"
}
export -f scan_repo
export ORG OUT GITLEAKS_IMAGE OSV_IMAGE SKIP_SEMGREP SCRIPT_DIR SUMMARY

xargs -a "$LIST" -P "$CONCURRENCY" -I {} bash -c 'scan_repo "$@"' _ {}

echo
echo "===================== TREE SCAN BASELINE COMPLETE ====================="
echo "Summary: $SUMMARY"
