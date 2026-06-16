# OSV-Scanner PR-diff mode — Implementation & Testing Plan

## Goal

Block a PR only when it introduces a vulnerable dependency not already present on the base branch, instead of failing on the repo's entire pre-existing vuln backlog. Keep the no-SARIF/no-GHAS constraint (must work on private repos without GitHub Advanced Security).

## Approach

Manual double-scan + diff inside the `sca-scan` job in `.github/workflows/pr-security.yml`. Scan the base ref, scan the PR head, fail only on vuln keys present in head but not in base.

## Implementation steps

1. Checkout with `fetch-depth: 0` so both base.sha and head commit are available.
2. Resolve refs from the event payload: base = `${{ github.event.pull_request.base.sha }}`, head = `${{ github.event.pull_request.head.sha }}` (use head.sha, NOT github.sha which is the merge commit).
3. Scan both refs emitting JSON (`--format json`), wrapping each docker run in `|| true` because OSV exits non-zero on findings and that must not abort the script before the diff.
4. Build a vuln key set per scan: `id + package + version` (so a version bump that drops one vuln and adds another is handled correctly). Parse with jq.
5. Diff with `comm -13 base_keys head_keys` to get newly-introduced vulns.
6. Decide: non-empty new set -> print `::error::` listing them + `exit 1`; else pass.
7. Edge cases handled explicitly:
   - No lockfile in either ref -> both empty -> pass.
   - Lockfile ADDED in PR -> all its vulns are new -> flagged.
   - Base scan produces no JSON (glitch) -> treat base as empty (fail-safe = over-report, never under-report) and log it.
   - Dep removed/upgraded to fixed version -> not in head set -> pass.
8. Rollout safety: ship with `continue-on-error: true` still on during validation; remove it (promote to blocking + add back to comment-on-failure needs) only after the test matrix passes.

Core step sketch (the real version lives in the job):

```bash
img=ghcr.io/google/osv-scanner:v1.9.1
key() { jq -r '.results[]?.packages[]? as $p | $p.vulnerabilities[]?.id
                | "\(.)|\($p.package.name)|\($p.package.version)"' "$1" | sort -u; }
git checkout ${{ github.event.pull_request.base.sha }} -q
docker run --rm -v "$PWD:/src" $img --recursive --format json /src > base.json || true
git checkout ${{ github.event.pull_request.head.sha }} -q
docker run --rm -v "$PWD:/src" $img --recursive --format json /src > head.json || true
comm -13 <(key base.json) <(key head.json) > new.txt
[ -s new.txt ] && { echo "::error::New vulnerable deps:"; cat new.txt; exit 1; } || echo "No new vulnerable deps."
```

## Testing plan (on the test repo to be provided)

| # | Scenario | Expected result |
|---|----------|-----------------|
| 1 | Touch only non-dependency code (repo already has a vulnerable lockfile) | Pass (proves backlog no longer blocks) |
| 2 | Add a known-vulnerable dep (e.g. `lodash@4.17.20`) | Fail, lists exactly the new vuln(s) |
| 3 | Upgrade a vulnerable dep to a fixed version | Pass |
| 4 | Remove a vulnerable dep | Pass |
| 5 | Add a clean dep | Pass |
| 6 | Repo/PR with no lockfile at all | Pass (no crash) |
| 7 | PR that introduces the lockfile | Fail if it contains vulns (all new) |

**Validation gates:** scenarios 1 + 2 are the must-pass pair. Confirm the `::error::` output names the specific package+CVE. Re-run scenario 1 against the real repo that produced the 100-vuln backlog to confirm it now passes.

## Effort & sequencing

Implementation ~1-1.5h (mostly jq extraction + edge cases). Testing ~1h for the 7 fixture PRs. Do it on a branch off main, keep warn-only through testing, promote to blocking in a final small commit once green.

## Risks / open questions

- Assumes the normal `pull_request` event (read-only token, fine — no untrusted code executed, only lockfiles parsed). Do NOT switch to `pull_request_target`.
- Scan time doubles (two full scans). Acceptable for a warn->block gate.
- jq JSON shape is pinned to OSV-Scanner v1.9.1 schema; re-verify `.results[].packages[].vulnerabilities[].id` if the image is bumped.
