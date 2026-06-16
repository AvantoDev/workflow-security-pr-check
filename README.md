# workflow-security-pr-check

Centralized, org-wide **PR security pipeline** for AvantoDev. One workflow, maintained
here, runs automatically on **every pull request across all repositories** and blocks
merge until the required security checks pass — with **zero per-repo configuration**.

---

## Table of contents

- [How it works (architecture)](#how-it-works-architecture)
- [What the pipeline checks](#what-the-pipeline-checks)
- [Blocking vs. warn-only](#blocking-vs-warn-only)
- [How to bypass / ignore a dependency finding](#how-to-bypass--ignore-a-dependency-finding)
- [Required org secrets & variables](#required-org-secrets--variables)
- [Operating & maintaining the pipeline](#operating--maintaining-the-pipeline)
- [Gotchas](#gotchas)
- [Future steps / roadmap](#future-steps--roadmap)
- [Repository layout](#repository-layout)

---

## How it works (architecture)

This pipeline uses **GitHub Organization Rulesets → "Require workflows to pass before
merging"** (sometimes called *required workflows*).

- The workflow lives **only in this repo** (`.github/workflows/pr-security.yml`).
- An **org ruleset** points every repo's default-branch PRs at this central workflow.
- GitHub runs the central workflow **in the context of each target repo** (it sees the
  target repo's code and secrets), and marks the result as a **required check**.

**Why this approach (vs. alternatives):**

| Approach | Why not chosen |
| --- | --- |
| Reusable workflow + a caller stub in every repo | Not zero-config; the stub lives in the target repo, so a malicious PR could edit it to disable/spoof the check. |
| GitHub App + hosted webhook server | Requires hosting, HA, key rotation — operational overhead not justified for commodity scanners. |
| **Org ruleset "require workflows" (this repo)** | **Tamper-proof** (workflow runs from the central repo, not the PR), **no server**, truly zero per-repo config, auto-enrolls new repos, single update point, native merge-block. |

**Tamper-resistance:** because the workflow definition is served from this central repo,
a PR in a target repo **cannot** modify, disable, or spoof the security checks by editing
its own workflow files. The ruleset also ignores the workflow's `on:` filters — it always
runs, so a PR can't skip the scan by avoiding certain paths.

```
┌─────────────────────────────┐         ┌──────────────────────────────┐
│ workflow-security-pr-check  │         │  Org Ruleset (Settings)      │
│  .github/workflows/         │◄────────│  "Require workflows to pass" │
│    pr-security.yml  (main)  │  points │  targets: all repos, default │
│    shai-hulud-guard.yml     │   at    │  branch, do_not_enforce_on_  │
└─────────────────────────────┘         │  create                      │
              │                          └──────────────────────────────┘
              │ runs in each target repo's context
              ▼
   PR in any AvantoDev repo ──► required check ──► merge blocked until green
```

> The pipeline runs from **`main`** of this repo. **Any change merged to `main` here goes
> live across all repos immediately.** Test changes on a branch + a throwaway PR in a test
> repo before merging (see [Operating & maintaining](#operating--maintaining-the-pipeline)).

---

## What the pipeline checks

Defined in [`.github/workflows/pr-security.yml`](.github/workflows/pr-security.yml). Each
scanner is an independent job; they run in **parallel**.

| Job | Tool | What it catches | Status |
| --- | --- | --- | --- |
| `shai-hulud-guard` | Inline IOC scan ([`shai-hulud-guard.yml`](.github/workflows/shai-hulud-guard.yml)) | Shai-Hulud supply-chain malware indicators (`SEC-2026-051501`) | 🔴 Blocking |
| `secrets-scan` | Gitleaks (binary, via Docker) | Hardcoded secrets / credentials in the repo & git history | 🔴 Blocking |
| `sast-scan` | Semgrep (`p/security-audit p/secrets p/owasp-top-ten`) | Code-level vulns: injection, XSS, insecure crypto, OWASP Top 10 | 🔴 Blocking |
| `sca-scan` | OSV-Scanner (PR-diff mode) | Known-vulnerable dependencies **newly introduced by the PR** | 🔴 Blocking |
| `actionlint` | actionlint | GitHub Actions workflow syntax/expression errors | 🟡 Warn-only |
| `zizmor` | zizmor | Actions security issues (injection, unpinned actions, broad permissions) | 🟡 Warn-only |
| `dockerfile-lint` | Hadolint | Dockerfile hardening / best practices | 🟡 Warn-only |
| `comment-on-failure` | add-pr-comment | Posts a PR comment when a **blocking** check fails | n/a |

### Notable design details

- **Shai-Hulud guard** is a self-contained reusable workflow (inline IOCs, no cross-repo
  fetch) so it works on private repos. It's referenced by full path
  (`AvantoDev/workflow-security-pr-check/.github/workflows/shai-hulud-guard.yml@main`) so it
  always resolves to this central repo regardless of the target.
- **Gitleaks and OSV-Scanner run the official Docker images directly**, not the marketplace
  action wrappers. The Gitleaks *action* requires a paid org license; the **binary is MIT**
  and free. The OSV *action* tag had no valid `action.yml` and its default SARIF upload
  would require GitHub Advanced Security on private repos — running the image avoids both.

### OSV-Scanner "PR-diff" mode (important)

OSV-Scanner does **not** fail on the repo's entire pre-existing vulnerability backlog.
It scans the PR's **base** commit and **head** commit, then fails **only on vulnerabilities
newly introduced by the PR** (a vuln key — `id|package|version` — present at head but not at
base). This keeps the gate practical across a large polyglot org: legacy debt doesn't block
every PR, but a PR that *adds* a vulnerable dependency is blocked.

It is multi-ecosystem: npm, PyPI, Go, Cargo, Maven/Gradle, RubyGems, Composer, NuGet, etc.
— so non-JS/Python repos are not silently unscanned.

---

## Blocking vs. warn-only

Controlled **per job** via `continue-on-error`:

- **Blocking** (no `continue-on-error`): a failure marks the required check red and **blocks
  merge**.
- **Warn-only** (`continue-on-error: true`): the job runs and surfaces findings in the logs
  but does **not** block. Promote a job to blocking by **removing** its `continue-on-error`
  line **and** adding the job to `comment-on-failure`'s `needs:` list.

Philosophy: start strict where signal is high (secrets, supply-chain, SAST, new vulns),
soft where it's noisy (lint), then promote as findings are tuned.

---

## How to bypass / ignore a dependency finding

Sometimes a PR must ship with a dependency that has a known, unfixed advisory (no patch
available yet, or the vuln is not reachable in your usage). OSV-Scanner supports an ignore
list via an **`osv-scanner.toml`** at the **repo root**.

### ⚠️ Security model — read this first

Ignores are **only honored from the repository's base branch** (the already-merged,
reviewed code). The pipeline:

1. Reads `osv-scanner.toml` from the **base commit** (trusted) and applies it via `--config`.
2. **Deletes any in-tree `osv-scanner.toml`** before scanning, so an untrusted ignore list
   present in the **PR head cannot auto-apply**.

This closes a **self-approval bypass**: a single PR cannot both introduce a vulnerable
dependency *and* add an ignore entry that suppresses it. **An ignore only takes effect after
it has been merged to the base branch** (i.e. after passing review + the gate itself).

### The correct workflow to ignore a dependency

1. Open a **dedicated PR** that adds/edits `osv-scanner.toml` at the repo root — *without*
   introducing the vulnerable dependency in the same PR. Example:

   ```toml
   # osv-scanner.toml (repo root)
   [[IgnoredVulns]]
   id = "GHSA-xvch-5gv4-984h"      # the advisory ID OSV reported
   # ignoreUntil = 2026-09-01      # optional: auto-expire the ignore
   reason = "No upstream fix yet; input is validated before reaching minimist. Re-review Sep 2026."
   ```

2. Get that PR **reviewed and merged** to the default branch. (Reviewers should treat ignore
   entries as a security decision — require a `reason`, prefer an `ignoreUntil` expiry.)

3. Now the dependency PR can merge: the advisory is on **base**, so OSV will suppress it.

> If you add the dependency and the ignore in the **same** PR, the gate will **still block**
> — by design. Split them into two PRs.

---

## Required org secrets & variables

All configured at **GitHub → Organization → Settings → Secrets and variables → Actions**.
Scope them to all repositories (or include private repos) so each target repo's run can read
them.

| Name | Type | Required? | Purpose / where to get it |
| --- | --- | --- | --- |
| `GITHUB_TOKEN` | secret | auto | Provided automatically per run — do not create. Used by Gitleaks, zizmor, the PR comment, and OSV checkout. |
| `SEMGREP_APP_TOKEN` | secret | optional | Semgrep Cloud reporting. Semgrep still runs without it (inline rules). [semgrep.dev](https://semgrep.dev) → Settings → Tokens. |

The core blocking scanners (Shai-Hulud, Gitleaks, Semgrep rule-based, OSV) need **no
secrets** and work out of the box.

> **Org secret access policy:** make sure optional tokens are visible to private repos, or
> runs there will read them as empty.

---

## Operating & maintaining the pipeline

### Golden rule
**`main` is production.** A merge here changes the gate for every repo. Always:

1. Branch off `main`, make the change.
2. Validate on a **test repo** (e.g. `back-file-manager-ms`) by opening a throwaway PR and
   reading the relevant job's **log** (not just the check status — warn-only jobs show
   "pass" even when they detect something).
3. Merge once validated. Clean up the test PR/branch.

### Required repo prerequisites (org-wide, set once)
- **GitHub Actions must be enabled** on every target repo. A required check that *can't run*
  (Actions disabled) never reports status and **wedges merges**. Enable org-wide:
  ```bash
  gh api -X PUT orgs/AvantoDev/actions/permissions \
    -f enabled_repositories=all -f allowed_actions=all
  ```
- **This repo's Actions access** must be org-wide (so target repos can call the reusable
  Shai-Hulud guard):
  ```bash
  gh api -X PUT repos/AvantoDev/workflow-security-pr-check/actions/permissions/access \
    -f access_level=organization
  ```

### Promoting a warn-only job to blocking
1. Remove its `continue-on-error: true` line.
2. Add the job name to `comment-on-failure`'s `needs:` array.
3. Validate on the test repo, then merge.

### Pinning (recommended hardening)
Action and image versions are currently pinned by tag (e.g. `osv-scanner:v1.9.1`,
`gitleaks:v8.21.2`, `actions/checkout@v4`). For stronger supply-chain integrity, pin to
**commit SHAs**. (zizmor will flag unpinned actions — that warn-only job is your own nudge.)

---

## Gotchas

- **Ruleset ignores `on:` filters** — the workflow always runs; a PR can't skip it by not
  touching certain paths. Keep `on:` minimal.
- **Bot / Dependabot PRs:** events triggered by `GITHUB_TOKEN` may not fire the check. A
  required check that never runs can't pass and will block the merge. Test Dependabot PRs;
  add a bypass actor or carve-out if needed.
- **Fork PRs:** `pull_request` gives a read-only token, so the failure-comment can't post on
  fork PRs. Do **not** switch to `pull_request_target` unless you accept external forks — and
  never check out/run untrusted PR code under it.
- **New empty repos/branches:** a required workflow can block branch creation. The ruleset
  sets `do_not_enforce_on_create: true` to avoid this.
- **Ruleset updates are full-replace (PUT)** — edit the ruleset JSON (source of truth) and
  re-apply; don't hand-edit in the UI and lose drift.
- **OSV PR-diff doubles scan time** (base + head). Acceptable for the gate; revisit for very
  large monorepos.
- **Warn-only jobs show "pass" even on findings** — always read the **log** when validating.

---

## Future steps / roadmap

Tracked work and natural next improvements:

- [ ] **`apply-ruleset.sh` + `org-security-ruleset.json`** — reproducible `gh` script to
      create/flip/delete the org ruleset (currently created via UI). Make the ruleset
      config version-controlled and the source of truth.
- [ ] **Dependabot PR test** — explicitly confirm the required check fires (or add a
      carve-out) so bot PRs don't wedge.
- [ ] **Promote warn-only jobs** (Hadolint, actionlint, zizmor) to blocking once tuned.
- [ ] **Pin actions/images to SHAs** for supply-chain integrity.
- [ ] **Broaden coverage** (the pipeline is designed to be extensible — add jobs):
  - IaC / cloud misconfig scanning (Checkov / KICS / tfsec) for Terraform, K8s, Helm.
  - Container **image** CVE scanning (Trivy / Grype) — distinct from Hadolint's linting.
  - Malicious dependency **behavior** detection (Socket) — install scripts, obfuscation,
    typosquats — beyond known-CVE SCA. (Gate behind an org var + API key.)
  - License-compliance policy on dependencies.
- [ ] **OSV ignore governance** — consider failing the ignore-PR if entries lack a `reason`
      or `ignoreUntil`, and a periodic job to report expired ignores.
- [ ] **Gitleaks tuning** — it scans full history and blocks on any pre-existing secret;
      consider a baseline/allowlist for legacy findings if rollout friction is high.

---

## Repository layout

```
.
├── .github/workflows/
│   ├── pr-security.yml        # the central PR security pipeline (runs org-wide)
│   └── shai-hulud-guard.yml   # reusable, self-contained Shai-Hulud IOC scan
├── docs/
│   └── osv-pr-diff-plan.md    # design + test matrix for OSV PR-diff mode
└── README.md                  # you are here
```

---

## References

- Shai-Hulud advisory: `SEC-2026-051501`
- OSV-Scanner: <https://google.github.io/osv-scanner/>
- Gitleaks: <https://github.com/gitleaks/gitleaks>
- Semgrep: <https://semgrep.dev>
- GitHub required workflows / org rulesets:
  <https://docs.github.com/en/enterprise-cloud@latest/actions/using-workflows/required-workflows>
