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

# Code appended after a long run of spaces, so it sits off-screen in a diff. The token must follow
# the padding — `.` never crosses a newline in grep, so the match stays on one line.
PADDED_CODE_RE=' {200,}.*(require[[:space:]]*\(|module\.exports|process\.env|child_process|global[.[]|function[[:space:]]*\(|=>[[:space:]]*[{(]|eval[[:space:]]*\()'

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
SELF_TOOLING_PATHS=(
  'tree-ioc-scan\.sh'
  'scan-machine\.js'
  'gitleaks-baseline\.sh'
  # `.reusable.yml` matters: the callable workflow in consuming repos is named
  # shai-hulud-guard.reusable.yml, and the previous `shai-hulud-guard\.ya?ml$`
  # could not match it — the guard's own pattern list blocked every PR in any
  # repo that vendored it. Anchored to .github/workflows/ so the exemption
  # cannot be claimed by a file that merely borrows the name: a payload at
  # src/vendor/shai-hulud-guard.reusable.yml is still scanned.
  '\.github/workflows/shai-hulud-guard(\.reusable)?\.ya?ml'
  'pr-security\.ya?ml'
  '\.security-allowlist'
  # The shai-hulud-guard toolkit vendored into product repos: a scanner, a
  # pre-commit hook, git-filter-repo purge rules, and the runbooks beside them.
  # Each is a list of IOC strings by construction, exactly like this script.
  'security/shai-hulud-guard/scan-shai-hulud\.sh'
  'security/shai-hulud-guard/pre-commit'
  'security/shai-hulud-guard/README\.md'
  'security/shai-hulud-guard/claude-code-find-and-fix\.md'
  'security/shai-hulud-guard/history-purge/purge-history\.sh'
  'security/shai-hulud-guard/history-purge/shai-hulud-replace\.txt'
  'security/shai-hulud-guard/history-purge/README\.md'
)
SELF_TOOLING_RE="(^|/)($(IFS='|'; printf '%s' "${SELF_TOOLING_PATHS[*]}"))\$"

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
      *.md|*.markdown|*.mdx|*.txt|*.rst|*/README*|*/CHANGELOG*|*docs/*) doc_like=1 ;;
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
