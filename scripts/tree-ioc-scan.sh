#!/usr/bin/env bash
#
# tree-ioc-scan.sh — malware/IOC gate for the PR Security Pipeline.
#
# Runs against the CHECKED-OUT TREE, not a diff. That is a deliberate design
# decision and the most important property of this script:
#
#   This worm family uses EVIL MERGES -- merge commits whose tree carries the
#   payload while BOTH parents are clean. Anything that diffs a commit against
#   its parent, or excludes merges (`git log --no-merges`), finds nothing.
#   For `pull_request` events GitHub checks out the MERGE RESULT, so scanning
#   the tree sees exactly what would land on the base branch.
#
# Why an extension allowlist is the wrong shape for this threat:
#
#   The guard this replaces restricted itself to *.js/*.cjs/*.mjs/*.ts/*.tsx/
#   *.jsx. This worm family ships its dropper as a binary-looking asset -- e.g.
#   JavaScript named `fa-solid-400.woff2` -- and launches it from
#   `.vscode/tasks.json`. Neither extension was covered, so the malicious files
#   were never opened at all, even though the dropper contained patterns the
#   guard already knew. Hence: read every tracked text file, and verify asset
#   extensions by magic bytes rather than trusting the name.
#
# Design rules:
#
#   * FAIL CLOSED. An internal error exits 3 and the CI job treats that as a
#     failure. A tool that suppresses its own errors and still emits a verdict
#     produces confident false clean results; silence is never success.
#   * Detect the SHAPE, not just the sample. A known filename will not be
#     reused; "a text/script file wearing a binary extension" will be.
#   * Magic bytes, never content heuristics. Asking "do the first 400 bytes
#     contain `=>` or `const`" matches compressed binary by chance and produces
#     large numbers of false positives on ordinary images.
#   * Allowlist resolved from the BASE commit only, matching the convention
#     already used here for osv-scanner.toml and .gitleaks.toml: a PR must not
#     be able to introduce a finding AND self-approve its suppression.
#
# Usage:
#   scripts/tree-ioc-scan.sh [--allowlist FILE] [--max-bytes N] [path ...]
#
# Exit: 0 clean · 1 confirmed indicator (block the merge) · 3 internal error
#
set -uo pipefail

ALLOWLIST=""
MAX_BYTES=$((2 * 1024 * 1024))
ROOTS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --allowlist) ALLOWLIST="${2:-}"; shift 2 ;;
    --max-bytes) MAX_BYTES="${2:-$MAX_BYTES}"; shift 2 ;;
    -h|--help)   sed -n '2,45p' "$0"; exit 0 ;;
    *)           ROOTS+=("$1"); shift ;;
  esac
done

# Any unexpected failure must block, never pass.
trap 'ec=$?; [ "$ec" -ne 0 ] && [ "$ec" -ne 1 ] && { echo "::error::tree-ioc-scan failed internally (exit $ec) — FAILING CLOSED"; exit 3; }' EXIT

command -v git >/dev/null 2>&1 || { echo "::error::git not available"; exit 3; }

# ── IOC patterns, by campaign ───────────────────────────────────────────────
# NOTE FOR READERS AND FOR SCANNERS: the strings below containing `eval(atob(`
# and `eval(Buffer.from(` are DETECTION PATTERNS — regexes used to find that
# construct in files under review. This script never evaluates anything; it only
# greps. Every element here is inert data passed to `grep -E`.
#
# CONFIRMED: no legitimate use. A hit blocks the merge.
CONFIRMED_IOCS=(
  # npm wave
  '5-3-343'
  '_\$_913e'
  "global\['_V'\]"
  'TCqf6ZkaQD84vYsC2cuu1jRwB6JveTaRrF'
  'TFMryB9m6d4kBMRjEVyFRbqKSV1cV2NcpH'
  '0x9d202c824402ca89e9aaccd2390b6f8b332ae743caa1469c695feb2781d56519'
  '0x3d2075f97b7b1e3234bd653779d21c605d7d8c6ec9c98d983880be5c7f4f9471'
  # VS Code auto-run + blockchain-resolved (EtherHiding) C2
  '0xa322E5f3D311D3080e6f0121063e9aDC2490Ef1a'
  'fa-solid-400'
  'x-payload-b64'
  '/0x/(cls|ls)'
  'Sec-V'
  '166\.88\.8\.133'
  # curl|bash on folder open. Matched by PATTERN, not
  # by the single host observed: `vscode-extension-260120.vercel.app` is a
  # disposable deployment name that can be republished in seconds.
  'vscode-extension-[0-9]+\.vercel\.app'
  '/settings/(linux|win)\?flag='
  # Generic across all waves: decode-then-execute.
  #
  # These require BOTH halves of the construct on one line — an `eval(` and a
  # base64 *literal* being decoded inside it — because either half alone is
  # ambiguous:
  #
  #   * `eval(` adjacent to `atob` is NOT how the observed payload is written.
  #     The AvantoDev Form A is
  #       bootstrap();<~1000 spaces>eval("global.i='5-3-343';"+atob('<base64>'))
  #     where `eval(` is followed by a string literal, not by `atob`. The
  #     previous `eval[[:space:]]*\([[:space:]]*atob` therefore did not match the
  #     real sample; it only matched prose *describing* it as `eval(atob(...))`.
  #     Every hit it produced across the org was a security document quoting the
  #     campaign, which is how a gate earns a reputation for crying wolf.
  #   * `atob('<base64>')` alone is ordinary code. Tests and data-URI handling
  #     decode base64 constantly. Blocking that would make the gate unusable.
  #
  # Requiring the pair keeps the true positive and drops the noise. `.` never
  # crosses a newline in grep, so the 80-char window stays on one line.
  #
  # The quote class includes a backtick (template literals) and the charset
  # includes `-_` (base64url), because a one-character encoding change must not
  # defeat the pattern — see the "Detect the SHAPE, not just the sample" rule
  # above.
  "eval[[:space:]]*\(.{0,80}atob[[:space:]]*\([[:space:]]*['\"\`][A-Za-z0-9+/_-]{32,}"
  "eval[[:space:]]*\(.{0,80}Buffer\.from[[:space:]]*\([[:space:]]*['\"\`][A-Za-z0-9+/_-]{32,}"
  # …and the same construct with the payload held in a VARIABLE rather than
  # inline, which the two literal patterns above cannot see:
  #     var p='<base64>';eval(atob(p))
  #     eval(Buffer.from(p,'base64'))
  #     eval(atob(decodeURIComponent(p)))
  # Decoding straight into `eval` has no legitimate use regardless of where the
  # argument comes from. Requiring an IDENTIFIER character after the paren —
  # rather than `.` — is what keeps prose `eval(atob(...))` and `eval(atob())`
  # clean, so this restores the coverage without reintroducing the noise.
  'eval[[:space:]]*\([[:space:]]*(atob|Buffer\.from)[[:space:]]*\([[:space:]]*[A-Za-z_$]'
  'Shai-Hulud: Here We Go Again'
  # Family shape markers. These match the loader's own output format rather than
  # any one sample's strings, so a rebuild with renamed variables still matches.
  # Keep these ahead of sample-specific strings when triaging a hit.
  '_\$_[0-9a-f]{4}[[:space:]]*=[[:space:]]*\(function'
  "global[.[]['\"]?[oi]['\"]?]?[[:space:]]*=[[:space:]]*['\"][0-9]+-[0-9A-Za-z-]*['\"]"
)

# A shell pipeline that executes something fetched from the network.
PIPED_EXEC='(curl|wget|iwr|Invoke-WebRequest)[^|]*\|[[:space:]]*(ba|z)?sh|(curl|wget|iwr)[^|]*\|[[:space:]]*(cmd|powershell|pwsh)'

# Code appended after a long run of spaces, so it sits off-screen in a diff.
#
# THREE conditions, all load-bearing:
#   1. a NON-WHITESPACE char BEFORE the run — without it the rule matches leading INDENTATION, not
#      appended padding. Deeply nested XAML clears 200 spaces unaided; this produced ~9,500 phantom
#      hits on a single UiPath repo and falsely flagged ~35 of them. Payload is code->pad->code;
#      indentation is pad->code. Found by Christian Mejia, 2026-08-13.
#      The class must be NON-WHITESPACE, not merely non-space: `[^ ]` accepts a TAB, so ordinary
#      mixed indentation — `<tab><250 spaces>require(` — still matched. Found by CodeRabbit on #17.
#   2. the token AFTER the run     — otherwise `const p = require("path");<300 spaces>trailing note`
#      is flagged, an ordinary file whose token merely precedes the run. (CodeRabbit, #14.)
#   3. 200 spaces, not fewer       — measured: 0 false positives over 1,742,964 real files, while
#      5,471 files carry runs of 80-199. Do not lower it.
# `.` never crosses a newline in grep, so the match stays on one line.
PADDED_CODE_RE='[^[:space:]] {200,}.*(require[[:space:]]*\(|module\.exports|process\.env|child_process|global[.[]|function[[:space:]]*\(|=>[[:space:]]*[{(]|eval[[:space:]]*\()'

# Executing a file that carries a binary asset extension. Nothing legitimate
# runs `node something.woff2`. This is what promotes an auto-run task from a
# bland "runs something on folder open" to a confirmed finding.
EXEC_DISGUISED='(node|nodejs|python3?|deno|bun|sh|bash|zsh|powershell|pwsh)[[:space:]]+[^[:space:]"'"'"';|&]*\.(woff2?|ttf|otf|ttc|eot|png|jpe?g|gif|ico|pdf|svg|mp[34]|webp)'

# ── Expected magic bytes per extension (hex prefix, alternatives with |) ─────
expected_magic() {
  case "$1" in
    png)      echo '89504e47' ;;
    jpg|jpeg) echo 'ffd8ff' ;;
    gif)      echo '474946' ;;
    woff)     echo '774f4646' ;;
    woff2)    echo '774f4632' ;;
    otf)      echo '4f54544f' ;;
    ttc)      echo '74746366' ;;
    ttf)      echo '00010000|74727565|74746366' ;;
    ico)      echo '00000100' ;;
    pdf)      echo '25504446' ;;
    webp)     echo '52494646' ;;
    *)        echo '' ;;
  esac
}

# ── Security tooling quotes IOCs by design ──────────────────────────────────
# Found in testing: this script blocked ITSELF, because its own pattern list is
# a file full of IOC strings. That matters beyond vanity — this pipeline runs on
# this repo's own pull requests, so without the exclusion every PR here would be
# unmergeable, and the natural "fix" under deadline pressure is to disable the gate.
#
# Scoped to specific known paths, NOT a blanket "skip anything under scripts/".
# A broad exclusion is how a real payload gets parked in an ignored directory.
# For the same reason every entry below is a full path suffix rather than a bare
# basename wherever the basename alone is generic: `pre-commit` and `README.md`
# must only be exempt inside the guard's own directory, never repo-wide.
# EXACT repo-relative paths, anchored at both ends. Not suffixes.
#
# This list used to be matched with a `(^|/)…$` prefix, which is a SUFFIX match: every entry was
# also exempt at any depth, so `vendor/security/shai-hulud-guard/scan-shai-hulud.sh` — or any path
# ending in one of these — skipped the scan. The comment here claimed the opposite. An exemption
# list an attacker can satisfy by choosing a directory name is the same defect as the `*docs/*`
# folder rule removed in this change, and it is worse here because these entries skip the file
# entirely rather than downgrading it to a warning. Found by CodeRabbit on #15.
#
# A repo that vendors this tooling at a non-canonical path gets a finding, and uses
# `.security-allowlist` on the base branch. That is the fail-closed direction: an unrecognised copy
# of a scanner is reviewed once, rather than every lookalike path being trusted forever.
SELF_TOOLING_PATHS=(
  # This repo's own tooling.
  'scripts/tree-ioc-scan\.sh'
  'scripts/gitleaks-baseline\.sh'
  '\.github/workflows/pr-security\.ya?ml'
  '\.github/workflows/shai-hulud-guard\.ya?ml'
  '\.security-allowlist'
  # The reusable guard as vendored into consuming repos.
  '\.github/workflows/shai-hulud-guard\.reusable\.ya?ml'
  # The shai-hulud-guard toolkit vendored into product repos: each is a list of IOC strings by
  # construction, exactly like this script.
  'security/shai-hulud-guard/scan-shai-hulud\.sh'
  'security/shai-hulud-guard/pre-commit'
  'security/shai-hulud-guard/drift-check\.sh'
  # The git hooks. _shared.sh IS the marker definition the hooks share, so it cannot avoid
  # containing the strings — it is the same class as scan-shai-hulud.sh, and without these entries
  # every repo that vendors the hooks blocks its own PRs on the security control it just installed.
  'security/shai-hulud-guard/hooks/_shared\.sh'
  'security/shai-hulud-guard/hooks/pre-commit'
  'security/shai-hulud-guard/hooks/post-checkout'
  'security/shai-hulud-guard/hooks/post-merge'
  'security/shai-hulud-guard/hooks/install\.sh'
  'security/shai-hulud-guard/hooks/README\.md'
  'security/shai-hulud-guard/README\.md'
  'security/shai-hulud-guard/claude-code-find-and-fix\.md'
  'security/shai-hulud-guard/history-purge/purge-history\.sh'
  'security/shai-hulud-guard/history-purge/shai-hulud-replace\.txt'
  'security/shai-hulud-guard/history-purge/README\.md'
  # Machine-scan tooling and the SEC-2026-0807 response scripts. Same class: they sweep for the
  # campaign, so they quote its markers by design.
  'docs/incidents/machine-scan/scan-machine\.js'
  'docs/incidents/scripts/sec-2026-0807-inventory\.sh'
  'docs/incidents/scripts/sec-2026-0807-bare-inventory\.sh'
  'docs/incidents/scripts/sec-2026-0807-credential-scan\.sh'
  'docs/incidents/scripts/sec-2026-0807-restore-branches\.sh'
)
# Anchored at BOTH ends: the path must be the whole repo-relative path, not a tail of it.
# ── Hash-pinned exemptions ──────────────────────────────────────────────────
# A path-only exemption is a trust assumption: "a file at this path is ours". That is a hole — a
# payload written to exactly security/shai-hulud-guard/hooks/_shared.sh would be skipped entirely,
# no IOC scan and no magic-byte check. Anchoring the path (#15) stops vendor/…/_shared.sh from
# claiming it, but not the canonical path itself.
#
# So for the hooks the exemption is granted by CONTENT, not by name: exempt only when the SHA-256
# matches. Same trust-anchor pattern as the evidence-manifest pin in scan-machine.js, where an
# unpinned self-signed manifest grants nothing.
#
# THE COST IS REAL: editing a hook in ai-claude-agents without updating the hash here makes every
# repo carrying the hooks fail this check. That is why the mismatch message names the file, every
# accepted hash and the exact fix — a confusing block gets the control deleted, an actionable one
# gets it fixed. Regenerate with:  sha256sum security/shai-hulud-guard/hooks/*
#
# TRANSITIONS: a path may list MORE THAN ONE hash, and any listed hash is accepted. This exists
# because the hook and its pin live in DIFFERENT REPOS and therefore cannot land in the same
# instant. With one hash per path, every hook edit is a flag day: the moment the edit merges to
# ai-claude-agents, either main or the in-flight PR is guaranteed to fail, whichever way the pin
# points. That is not hypothetical — ai-claude-agents#85 changed _shared.sh, the pin was moved
# forward to the version in the then-unmerged #86, and every PR opened in between failed closed on
# a file none of them touched.
#
# So the procedure for changing a hook is:
#   1. ADD the new hash here, keeping the outgoing one. Both revisions now pass.
#   2. Land the hook change in ai-claude-agents, at whatever pace review takes.
#   3. DELETE the outgoing hash once nothing references it. Leaving it is not a hole — it is a
#      revision that was reviewed — but the list should describe the present, so prune it.
# Each entry is still an explicit, reviewed decision to trust one exact byte sequence; listing two
# accepts two known revisions, it does not relax the check.
#
# That glob covers EVERY file in the directory, so SELF_TOOLING_PATHS must list every file in the
# directory too. A file under the pinned prefix but MISSING from SELF_TOOLING_PATHS never reaches the
# "pinned but no hash recorded" error — is_self_tooling() returns 1 at the path test and the file is
# quietly scanned as ordinary content. That is how hooks/README.md sat unlisted: it was added after
# the pin, this glob picked it up, the path list did not. Harmless while it contains no markers, and a
# silent trap the day it documents one verbatim.
#
# Entries in SELF_TOOLING_PATHS that are NOT under the pinned prefix stay path-only by design:
# scan-machine.js and the vendored toolkit are versioned per repo, so pinning them would break every
# consumer sitting on a different revision.
SELF_TOOLING_HASHES="
0a8e462801a440b17a5d6947a3caa8a278cfdde0bc9dc2e545fe79652039bfb6  security/shai-hulud-guard/hooks/_shared.sh
# TRANSITIONAL — this is the version currently on ai-claude-agents main; the line above is the
# widened-marker version arriving in ai-claude-agents#89. Drop this once #89 has landed
# everywhere. It was removed in 3a142af (the re-pin replaced the hash instead of adding to it),
# which left main's own hook unrecognised and blocked every PR cut from main.
9e3c95c4a2f6a9a45a2ed2f70c3dee479b2c231e9348e1425d96742017d980af  security/shai-hulud-guard/hooks/_shared.sh
e363e5c1da49d2e0fa55049d825be57474be3d1d5c25a13b3c5646be7814dd05  security/shai-hulud-guard/hooks/pre-commit
b5712cc58850efd68eb58356a29fa8212afb271b6c9f1e3b50cb840be91a005f  security/shai-hulud-guard/hooks/post-checkout
a398d31098f07388da9ccfad6a9ff9d19398877005b535c3ad90ebb4cd3095a9  security/shai-hulud-guard/hooks/post-merge
5f77bb338d4e56da394d8da6701745a2d8c6b3a8e0336c238b13bc17f2ada365  security/shai-hulud-guard/hooks/install.sh
7d5f83994d86bae1ae3c7b7cb4149990aba5c4462481cdf66c22641251358319  security/shai-hulud-guard/hooks/README.md
# INCOMING — the husky-chaining revision in ai-claude-agents#94, at review revision 2 (af79a56).
# Revision 1 is SUPERSEDED, not retained: nothing is cut from that PR branch, so no other PR
# references it, and it had a reviewed vulnerability — .husky was chained unconditionally with the
# exec bit waived, so tree content executed on checkout. Never retain a revision you rejected.
# (Contrast the main trio above, which MUST stay: PRs are cut from main every day.) (sh_chain honours a recorded
# shaiHulud.chainTo and runs non-executable husky hooks through sh; install.sh gains --adopt).
# ADDED, not substituted: the three hashes above are what ai-claude-agents main serves today, so
# they stay until #94 has landed everywhere, or every PR cut from main fails closed on files it
# never touched — the 3a142af mistake recorded above. Prune the outgoing three once #94 is merged.
# Verified against refs/pull/94/head: detection is unchanged (MARKER_SET_VERSION and every SH_*
# rule byte-identical to main), and the diff only touches hook chaining and installation.
8ac0d757ed1cfb2721a2b86d0e5c92ed0a29eaabedce393585768ba564de3b40  security/shai-hulud-guard/hooks/_shared.sh
4e31fc0fa76a52ac5793ad64418f918f8dfbabe5ddd7813603cc473b23970840  security/shai-hulud-guard/hooks/install.sh
959d03d0b9f20195c79e8ccfc73fadfa6e7ae987522fb77ab82dd589a6ad67f3  security/shai-hulud-guard/hooks/README.md
"
# Kept separate from SELF_TOOLING_PATHS so adding a path cannot silently make it hash-pinned, and a
# typo in a hash cannot quietly disable the pin.
SELF_TOOLING_PINNED='^security/shai-hulud-guard/hooks/'

SELF_TOOLING_RE="^($(IFS='|'; printf '%s' "${SELF_TOOLING_PATHS[*]}"))\$"

is_self_tooling() {
  local p="$1" wants got
  printf '%s' "$p" | grep -qE "$SELF_TOOLING_RE" || return 1

  # Not hash-pinned: path match is the whole test (legacy entries, versioned per repo).
  printf '%s' "$p" | grep -qE "$SELF_TOOLING_PINNED" || return 0

  # Hash-pinned: content decides. A path may list MORE THAN ONE hash and any of them is
  # accepted — see "Transitions" above. Trust is still granted only to contents somebody
  # wrote down here, so N accepted hashes is N reviewed revisions, not a wildcard.
  wants="$(printf '%s\n' "$SELF_TOOLING_HASHES" | awk -v f="$p" '$2==f{print $1}')"
  if [ -z "$wants" ]; then
    echo "::error file=$p::listed as hash-pinned self-tooling but no hash is recorded — scanning it. Add its sha256 to SELF_TOOLING_HASHES in workflow-security-pr-check."
    return 1
  fi
  got="$(sha256sum "$p" 2>/dev/null | cut -d' ' -f1)"
  # -x so a truncated hash cannot match by prefix, -F so it is compared literally.
  if [ -n "$got" ] && printf '%s\n' "$wants" | grep -qxF "$got"; then
    return 0
  fi
  # Fail closed: an unrecognised version of a security hook is reviewed, not trusted.
  echo "::error file=$p::hook file does not match any pinned hash, so it is being SCANNED, not trusted."
  while IFS= read -r want; do
    [ -n "$want" ] && echo "::error file=$p::  accepted $want"
  done <<EOF
$wants
EOF
  echo "::error file=$p::  actual   ${got:-<unreadable>}"
  echo "::error file=$p::If you intentionally changed this hook, ADD its sha256 to SELF_TOOLING_HASHES in AvantoDev/workflow-security-pr-check (sha256sum security/shai-hulud-guard/hooks/*) — keep the outgoing hash listed until the change has landed everywhere, then drop it. If you did not change it, STOP and report it."
  return 1
}

# ── Allowlist (one glob or literal path per line; '#' comments) ──────────────
allowed() {
  [ -n "$ALLOWLIST" ] && [ -f "$ALLOWLIST" ] || return 1
  local p="$1" pat
  while IFS= read -r pat; do
    pat="${pat%%#*}"; pat="$(printf '%s' "$pat" | tr -d '[:space:]')"
    [ -z "$pat" ] && continue
    # shellcheck disable=SC2053  # glob match is intended
    [[ "$p" == $pat ]] && return 0
  done < "$ALLOWLIST"
  return 1
}

confirmed=0
note() { echo "::error::$*"; confirmed=$((confirmed + 1)); }

# Tracked files only: an uncommitted node_modules must not create noise, and a
# payload that is not committed cannot reach the base branch.
mapfile -t FILES < <(
  if [ ${#ROOTS[@]} -gt 0 ]; then git ls-files -z -- "${ROOTS[@]}" | tr '\0' '\n'
  else git ls-files -z | tr '\0' '\n'; fi
) || { echo "::error::git ls-files failed"; exit 3; }

echo "tree-ioc-scan: ${#FILES[@]} tracked file(s) under review"

for f in "${FILES[@]}"; do
  [ -z "$f" ] && continue
  [ -f "$f" ] || continue                      # deleted/submodule entry
  is_self_tooling "$f" && { echo "  security tooling, skipped: $f"; continue; }
  allowed "$f" && { echo "  allowlisted: $f"; continue; }

  size=$(wc -c < "$f" 2>/dev/null || echo 0)
  ext="${f##*.}"; ext="$(printf '%s' "$ext" | tr '[:upper:]' '[:lower:]')"

  # ---- 1. Extension lies about content ------------------------------------
  # Detected structurally so the next variant under
  # a different filename is still caught.
  exp="$(expected_magic "$ext")"
  if [ -n "$exp" ] && [ "$size" -gt 8 ]; then
    magic=$(head -c 4 "$f" 2>/dev/null | od -An -tx1 -v 2>/dev/null | tr -d ' \n')
    if [ -n "$magic" ] && ! printf '%s' "$magic" | grep -qE "^($exp)"; then
      if head -c 512 "$f" 2>/dev/null | LC_ALL=C grep -qP '^[\x09\x0A\x0D\x20-\x7E]*$' 2>/dev/null \
         || head -c 512 "$f" 2>/dev/null | LC_ALL=C tr -d '\11\12\15\40-\176' | LC_ALL=C grep -q '^$'; then
        note "DISGUISED FILE: $f is plain text but claims to be .$ext (magic=$magic, expected ${exp//|/ or })
        A script wearing an asset extension is this family's delivery mechanism.
        If this file is legitimate (a git-lfs pointer, a placeholder), add its path to
        .security-allowlist on the BASE branch first."
      fi
    fi
  fi

  # ---- 2. Editor auto-run: the launcher -----------------------------------
  case "$f" in
    *.vscode/tasks.json|.vscode/tasks.json)
      if grep -qE '"runOn"[[:space:]]*:[[:space:]]*"folderOpen"' "$f" 2>/dev/null; then
        if grep -qE "$PIPED_EXEC" "$f" 2>/dev/null; then
          note "AUTO-RUN + REMOTE PAYLOAD: $f runs a task on folder open that pipes a fetched script into a shell.
        This executes the instant anyone opens the folder in VS Code or Cursor."
        elif grep -qE "$EXEC_DISGUISED" "$f" 2>/dev/null; then
          note "AUTO-RUN + DISGUISED PAYLOAD: $f runs a task on folder open that executes a file with a
        binary asset extension. Nothing legitimate runs a font or an image as code."
        else
          echo "::warning file=$f::runs a task automatically on folder open. Allowed, but review what it runs — a
        reviewer must confirm the command is local, is not fetched from the network, and is not an asset file."
        fi
      fi
      ;;
    *.vscode/settings.json|.vscode/settings.json)
      # The authorisation half. On its own it only removes a prompt, but combined
      # with a sibling folderOpen task it means silent execution with no warning.
      if grep -qE '"task\.allowAutomaticTasks"[[:space:]]*:[[:space:]]*"?(on|true)"?' "$f" 2>/dev/null; then
        if [ -f "$(dirname "$f")/tasks.json" ] && \
           grep -qE '"runOn"[[:space:]]*:[[:space:]]*"folderOpen"' "$(dirname "$f")/tasks.json" 2>/dev/null; then
          note "SILENT AUTO-RUN: $f pre-approves automatic tasks AND a folderOpen task sits beside it.
        Together these execute with no prompt the moment the folder is opened."
        else
          note "AUTO-RUN PRE-APPROVAL: $f commits \"task.allowAutomaticTasks\".
        This removes the confirmation prompt that protects every developer who opens this repo.
        It must not be committed — it is a per-developer choice, not a repository setting."
        fi
      fi
      if grep -qE '"security\.workspace\.trust\.enabled"[[:space:]]*:[[:space:]]*false' "$f" 2>/dev/null; then
        note "WORKSPACE TRUST DISABLED: $f commits security.workspace.trust.enabled=false.
        Workspace Trust is the control that stops an untrusted folder from executing tasks at all."
      fi
      ;;
  esac

  # ---- 3. IOC strings, in EVERY text file --------------------------------
  # No extension filter. That restriction is precisely what let the Aug 2026
  # payload through the previous guard.
  [ "$size" -gt "$MAX_BYTES" ] && continue
  if LC_ALL=C grep -qI . "$f" 2>/dev/null; then      # -I: skip binary
    # Prose about this threat necessarily contains its indicators: incident records,
    # runbooks, post-mortems and READMEs quote the strings they tell people to look for.
    # Blocking those is how a doc-only PR becomes unmergeable and how the gate acquires a
    # reputation for crying wolf — the same failure the eval(atob) pattern note above
    # describes, where every hit across the org was a security document.
    #
    # Downgraded to a warning rather than skipped. Markdown does not execute, so a hit here
    # is not a live payload; but a payload STAGED in a doc file before being moved is still
    # worth seeing, and a silent exclusion is an invisible hole in a security gate. The
    # finding stays in the log; it just does not block the merge.
    #
    # This matches the carve-out the piped-remote-exec check below already makes for docs.
    case "$f" in
      # BY FILE TYPE ONLY — never by folder, and never by filename.
      #
      # `*docs/*`, `*/README*` and `*/CHANGELOG*` were removed on 2026-08-12. A folder exemption is
      # a named place to park a payload: `docs/anything.js` would have been downgraded to a warning
      # purely because of where it sat, and an attacker who reads this file learns the directory to
      # use. A filename exemption has the same defect — `src/README.js` is not documentation.
      #
      # What remains is exempt because of what the format IS. Nothing in a toolchain reads a `.md`
      # or a `.txt` and executes it, so a marker in one is prose, not a payload. That reasoning does
      # NOT extend to `.json`, which is why it is absent: `package.json` runs `postinstall`,
      # `.vscode/tasks.json` runs on folder open — the delivery mechanism in this very family —
      # `devcontainer.json` runs `postCreateCommand`, and `.eslintrc.json`/`tsconfig.json` load
      # modules. JSON is read by a toolchain; Markdown is read by a human.
      #
      # Documentation that must quote a payload verbatim (incident records, decoded samples) belongs
      # in a `.md` or `.txt` file for exactly this reason.
      *.md|*.markdown|*.mdx|*.txt|*.rst) doc_like=1 ;;
      *) doc_like=0 ;;
    esac
    for p in "${CONFIRMED_IOCS[@]}"; do
      if hit=$(LC_ALL=C grep -nIE -m1 -e "$p" "$f" 2>/dev/null); then
        if [ "$doc_like" = "1" ]; then
          echo "::warning file=$f::IOC string in documentation (not blocking): ${hit:0:160}"
        else
          note "IOC in $f: ${hit:0:200}
        pattern: $p"
        fi
      fi
    done
    # ---- 3b. Appended-after-padding check ---------------------------------
    # Code appended to the end of an otherwise normal line, behind a long run of
    # spaces, so it sits off-screen in a diff. Structural: independent of which
    # strings the appended code happens to contain.
    #
    # Two conditions, both required: the padding run, and a code token on the
    # same line. Deliberately limited to code extensions — indented markup and
    # generated documents carry long space runs legitimately, and a check that
    # fires on those trains people to ignore it.
    case "$f" in
      *.js|*.cjs|*.mjs|*.ts|*.tsx|*.jsx|*.json|*.yml|*.yaml)
        # ONE suffix-aware regex, used for both the test and the offset.
        #
        # It must require the token AFTER the padding, not merely on the same line. A two-stage
        # "line has padding" AND "line has a token" test flags
        #   const p = require("path");<300 spaces>trailing note
        # which is an ordinary file with an oddly padded comment — the token precedes the run.
        # Using one regex for the offset too keeps the reported position on the run that actually
        # has code after it; taking the first ' {200,}' in the file can point at an unrelated
        # earlier run and send the reader to the wrong place.
        if LC_ALL=C grep -qE "$PADDED_CODE_RE" "$f" 2>/dev/null; then
          # Offset only, not the line: the match is thousands of characters wide and would bury
          # the rest of the log.
          col=$(LC_ALL=C grep -boE "$PADDED_CODE_RE" "$f" 2>/dev/null | head -1 | cut -d: -f1)
          note "APPENDED CODE AFTER PADDING: $f has code following a run of 200+ spaces (byte offset ${col:-?}).
        Nothing in a normal toolchain emits that. Open the file and scroll right, or run:
          grep -n ' \\{200,\\}' -- \"$f\" | sed 's/ \\{200,\\}/ <200+ spaces> /'"
        fi
        ;;
    esac

    # A piped remote-exec anywhere in a committed file is worth a warning even
    # outside .vscode — CI scripts and devcontainer hooks run automatically too.
    case "$f" in
      *.md|*.txt|*.rst|*/README*|*docs/*) : ;;       # documentation quotes these legitimately
      *)
        if LC_ALL=C grep -qE "$PIPED_EXEC" "$f" 2>/dev/null; then
          echo "::warning file=$f::fetches a remote script and pipes it into a shell. Confirm the host is trusted
        and pin what you execute; this is a known delivery pattern."
        fi
        ;;
    esac
  fi
done

echo
if [ "$confirmed" -gt 0 ]; then
  cat <<EOF
❌ BLOCKED — $confirmed confirmed indicator(s).

These are not style findings. Each one above has no legitimate use in this codebase.
See the internal incident record for campaign details.

If you are certain a finding is a false positive, add the path to .security-allowlist
on the BASE branch in a separate PR. The allowlist is deliberately NOT read from this
PR's head — a change must not be able to approve its own suppression.
EOF
  exit 1
fi
echo "✅ tree-ioc-scan: clean (${#FILES[@]} files, tree-based so evil merges are covered)"
exit 0
