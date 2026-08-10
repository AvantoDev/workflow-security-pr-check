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
  # Generic across all waves
  'eval[[:space:]]*\([[:space:]]*atob'
  'eval[[:space:]]*\([[:space:]]*Buffer\.from'
  'Shai-Hulud: Here We Go Again'
)

# A shell pipeline that executes something fetched from the network.
PIPED_EXEC='(curl|wget|iwr|Invoke-WebRequest)[^|]*\|[[:space:]]*(ba|z)?sh|(curl|wget|iwr)[^|]*\|[[:space:]]*(cmd|powershell|pwsh)'

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
SELF_TOOLING_RE='(^|/)(tree-ioc-scan\.sh|scan-machine\.js|gitleaks-baseline\.sh|shai-hulud-guard\.ya?ml|pr-security\.ya?ml|\.security-allowlist)$'

is_self_tooling() { printf '%s' "$1" | grep -qE "$SELF_TOOLING_RE"; }

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
    for p in "${CONFIRMED_IOCS[@]}"; do
      if hit=$(LC_ALL=C grep -nIE -m1 -e "$p" "$f" 2>/dev/null); then
        note "IOC in $f: ${hit:0:200}
        pattern: $p"
      fi
    done
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
