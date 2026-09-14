# Scheduled deep scan — runbook

Covers `.github/workflows/scheduled-deep-scan.yml` (ST-1014): the monthly, whole-org,
whole-tree scan that closes the gap `pr-security.yml` leaves by design — it only runs on
`pull_request` and only examines the diff, so anything pushed straight to a branch, or already
in a repo's tree before the gate existed, is never seen. This is the SEC-2026-0808 gap: that
intrusion sat undetected for roughly 6.5 months because nothing scanned outside a PR diff.

## Status: not yet fully operational

Two things block turning the real monthly `schedule:` trigger on:

1. **`ORG_SCAN_TOKEN`** (org secret) does not exist yet. The workflow's default `GITHUB_TOKEN`
   is scoped to this one repo and cannot enumerate or clone repos across an org, let alone
   across two orgs. This needs an org admin to provision a token (a GitHub App installation
   token is preferable to a long-lived PAT — see the PR description) with repo-read access to
   **both** `AvantoDev` and `AvantoDev-DreamIT`, including private, archived and fork repos.
   Confirmed during implementation: the credential available in this environment can see
   `AvantoDev` fully but has zero visibility into `AvantoDev-DreamIT` — that gap has to close
   before a full both-orgs run means anything.
2. **`SLACK_WEBHOOK_URL`** (org or repo secret) does not exist yet. No Slack integration exists
   anywhere else in this repo to extend. Needs a webhook (or bot token) and a channel named.
   Until it's set, the consolidation job logs a warning and skips posting — it does not fail
   the run.

Until both are in place: validate with `workflow_dispatch`, scoped via the `repo_subset` input
to a handful of known repos (this repo's own "golden rule" — validate on a test repo before
trusting a gate). Leave the `schedule:` cron dormant until an org admin confirms the token and
someone owns reading the monthly output.

## Who reads the monthly output

**TBD — confirm with Luis Mayz.** Placeholder until named: Luis Mayz / the security channel
that `SLACK_WEBHOOK_URL` posts to.

## What a finding triggers

- **Part A (`deep-scan-org.sh`) verdict `INFECTED_*`**: treat as a live incident, not a routine
  finding — this is the same tooling and detection family used to respond to SEC-2026-0807 and
  SEC-2026-0808. Do not clean up locally; follow the incident process those tickets used
  (central incident record, evidence preserved before any remediation, Luis as incident lead).
- **Part A `forged_commits.csv` rows**: review, don't auto-block. The heuristic (timezone
  mismatch, author≠committer, orphan commit, known actor email) also flags *every* repo's
  initial commit as "orphan" — that's expected noise in this script, not a bug. Root commits and
  genuinely suspicious forged commits both land in this file; only the latter matter.
- **Part B (`tree-scan-baseline.sh`) Gitleaks/OSV/Semgrep findings**: same severity judgment as
  the PR gate would apply — a real secret or vulnerable dependency in the tree needs a fix PR
  (rotate the credential first if it's a live secret). The Shai-Hulud IOC guard (`ioc_rc` column)
  follows the same fail-closed contract as `shai-hulud-guard.yml`: `1` is a confirmed indicator,
  `3` is an internal scanner error — both need a human look, `3` especially, since it means the
  scan couldn't reach a real verdict.

## Suppressing a false positive without weakening the scan

Mirrors the pattern already documented in the main [README](../README.md#how-to-bypass--ignore-a-dependency-finding)
for `pr-security.yml`: a repo's `osv-scanner.toml` / `.gitleaks.toml` / `.security-allowlist`
still applies, since Part B resolves config from the target repo's own tree (there is no PR
base/head to protect against self-approval on a scheduled run against already-merged code — see
the anti-self-approval note in `scripts/tree-scan-baseline.sh`). So the fix is the same one that
already applies to the PR gate: add a `reason` (and ideally an `ignoreUntil`) to the repo's own
suppression file, get that PR reviewed and merged, and the next scheduled/dispatched run picks
it up. Never edit the scan output or this workflow to hide a finding — the suppression lives in
the target repo, reviewed like any other change.

## Runtime and cost

**TBD.** Not yet measured — this workflow has not had a full `workflow_dispatch` run across
both orgs yet (blocked on the prerequisites above). Fill this in after the first real full-scope
run:

- Part A wall-clock time (per org, and total)
- Part B wall-clock time (per org, and total; note whether `skip_semgrep` was used)
- Estimated GitHub Actions minutes consumed (`ubuntu-latest` minute-multiplier applies)
- Whether either job approached its `timeout-minutes` budget (180 for Part A, 330 for Part B —
  both provisional guesses, not measured)

This is what answers the ticket's actual question: whether monthly is the right cadence, or
whether the runtime/cost argues for less frequent (e.g. quarterly) or more targeted scans.
