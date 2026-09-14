#!/usr/bin/env bash
#
# enumerate-org-repos.sh — dynamic, paginated repo enumeration for one GitHub org.
#
# ST-1014: deep-scan-org.sh takes a static repo-list file. A static list goes
# stale silently — the SEC-2026-0807 "267 repos" figure came from PushEvent
# history, not a scan, and would miss every repo created or renamed since.
# This walks the REST API directly with explicit pagination (not `gh repo
# list`, whose default filtering behaviour is less auditable) so private,
# archived and org-owned fork repos are all included, and prints exactly what
# was resolved so a scheduled run's log always shows real coverage.
#
# Usage:
#   ./enumerate-org-repos.sh <org> <output-file>
#
# Requirements: gh (authenticated with read access to the org, including
# private repos), jq.
#
# Output: one bare repo name per line in <output-file>, sorted, deduplicated —
# matching deep-scan-org.sh's <repo-list> format, which prepends ORG/ itself.
# Prints resolved counts (total / archived / fork) to stderr.
set -uo pipefail

ORG="${1:?usage: $0 <org> <output-file>}"
OUT="${2:?usage: $0 <org> <output-file>}"

for bin in gh jq; do
  command -v "$bin" >/dev/null 2>&1 || { echo "ERROR: '$bin' is required but not found." >&2; exit 1; }
done

tmp_json="$(mktemp)"
tmp_err="$(mktemp)"
trap 'rm -f "$tmp_json" "$tmp_err"' EXIT

# type=all returns private + public repos this credential can see. GitHub's
# list-repos endpoint does not let archived/fork repos be excluded up front —
# by design we don't want them excluded, so we keep them and report their
# counts instead of filtering.
if ! gh api --paginate "orgs/${ORG}/repos?type=all&per_page=100" \
     --jq '.[] | {name, archived, fork}' > "$tmp_json" 2> "$tmp_err"; then
  echo "ERROR: failed to enumerate repos for org '$ORG':" >&2
  cat "$tmp_err" >&2
  exit 1
fi

jq -r '.name' "$tmp_json" | sort -u > "$OUT"

total=$(wc -l < "$OUT" | tr -d ' ')
archived=$(jq -r 'select(.archived == true) | .name' "$tmp_json" | wc -l | tr -d ' ')
forks=$(jq -r 'select(.fork == true) | .name' "$tmp_json" | wc -l | tr -d ' ')

echo "enumerate-org-repos: org=$ORG resolved=$total (archived=$archived fork=$forks) -> $OUT" >&2
