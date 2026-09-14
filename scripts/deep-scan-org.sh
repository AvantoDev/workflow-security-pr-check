#!/usr/bin/env bash
#
# SEC-2026-0807 / DEEP ANALYSIS — full-history, all-refs scan of one GitHub org.
#
# Relocated here from ai-claude-agents:docs/incidents/SEC-2026-0807/tooling/
# for ST-1014, so it can run as a scheduled workflow instead of by hand off a
# laptop. Detection logic and safety properties are unchanged from the
# original incident-response script.
#
# Goes beyond sec-2026-0807-bare-inventory.sh, which only looks for the Aug-7
# Shai-Hulud payload path, folderOpen tasks, workflow IOCs and magic-byte
# mismatches. This adds the January dropper family, npm lifecycle hooks, the
# commit-forgery signature, contributor anomalies, and full IOC-string coverage
# over EVERY blob in EVERY ref (not just branch tips).
#
# SAFETY: bare clones only — no working tree, so no payload is ever written in
#         executable form. Nothing is ever checked out. Read-only against the
#         remote. Never open any of these directories in an editor.
#
# Usage: ORG=<org> ./deep-scan-org.sh <repo-list> <output-dir>
#
# The malware constants below are overridable via env for fixture testing
# (see .github/workflows/deep-scan-selftest.yml) — defaults are the real,
# incident-confirmed values and production runs never need to set them.

set -uo pipefail

ORG="${ORG:?set ORG=<github-org>}"
LIST="${1:?usage: ORG=<org> $0 <repo-list> <output-dir>}"
OUT="${2:?usage: ORG=<org> $0 <repo-list> <output-dir>}"
mkdir -p "$OUT" "$OUT/clones"

# ---- known-bad constants -------------------------------------------------
SH_BLOB="${SH_BLOB:-6df5b2c9c172d3b822494c3ef9083dbfc135ecf6}"          # Shai-Hulud dropper (git blob)
SH_SHA256="${SH_SHA256:-9fbb31129c04e8eb1a50519fc864c74d1b20d57c07d4099348f8fbc9a1a1eae6}"
SH_SIZE="${SH_SIZE:-9129}"
JAN_BLOB="${JAN_BLOB:-9c19ae8ddad77d28551b9c9e55230f0fe930c68b}"          # January curl|bash tasks.json
ACTOR_A="${ACTOR_A:-abdullahkhan-create}"

# IOC strings, checked against EVERY blob's content
IOC='vscode-extension-260120|fa-solid-400|0xa322E5f3D311D3080e6f0121063e9aDC2490Ef1a|Sec-V: A8|x-payload-b64|/0x/(cls|ls)|npm-cache\.com|pypi-get\.com|js-mirror\.com|Shai-Hulud|q4FZkxX|y-p_>d\$0B|eth\.drpc\.org|1rpc\.io/eth|blockscout|ethereum-rpc\.publicnode|eth-mainnet\.public\.blastapi'
# shell-pipe execution patterns (the January family and relatives)
PIPE='curl[^"]*\|[[:space:]]*(bash|sh|cmd|powershell)|wget[^"]*\|[[:space:]]*(bash|sh)|iwr[^"]*\|[[:space:]]*iex|Invoke-Expression'

hdr() { [ -s "$1" ] || echo "$2" > "$1"; }
F_SUM="$OUT/deep_summary.csv";     hdr "$F_SUM"  "repo,refs,commits,sh_payload,jan_dropper,autorun_refs,pipe_exec,npm_hooks,ioc_blobs,workflow_adds,forged_commits,verdict"
F_AUTO="$OUT/autorun.csv";         hdr "$F_AUTO" "repo,ref,blob,path,command"
F_IOC="$OUT/ioc_hits.csv";         hdr "$F_IOC"  "repo,blob,path,ioc"
F_NPM="$OUT/npm_hooks.csv";        hdr "$F_NPM"  "repo,blob,path,hook,command"
F_FORGE="$OUT/forged_commits.csv"; hdr "$F_FORGE" "repo,commit,author,author_date,committer,committer_date,reason,subject"
F_CONTRIB="$OUT/contributors.csv"; hdr "$F_CONTRIB" "repo,name,email,commits,flag"
F_WF="$OUT/workflows.csv";         hdr "$F_WF"   "repo,blob,path,ioc"

log() { echo "[$(date -u +%H:%M:%S)] $*"; }

while read -r repo; do
  [ -z "$repo" ] && continue
  d="$OUT/clones/$repo.git"
  log "=== $repo"
  if [ ! -d "$d" ]; then
    gh repo clone "$ORG/$repo" "$d" -- --bare --quiet 2>/dev/null || {
      log "    CLONE_FAILED"; echo "$repo,,,,,,,,,,,CLONE_FAILED" >> "$F_SUM"; continue; }
  fi
  G="git --git-dir=$d"

  # fetch PR refs too — they hold objects branches no longer reach
  $G fetch -q origin '+refs/pull/*:refs/remotes/pr/*' 2>/dev/null

  nrefs=$($G for-each-ref --format='%(refname)' | wc -l | tr -d ' ')
  ncommits=$($G rev-list --all --count 2>/dev/null || echo 0)

  # every object in every ref: "<sha> <path>"
  objs=$($G rev-list --all --objects 2>/dev/null)

  # -- 1. Shai-Hulud payload (by blob AND by content hash, path-independent) --
  sh_hit=0
  printf '%s\n' "$objs" | awk '{print $1}' | sort -u | while read -r b; do :; done
  if printf '%s\n' "$objs" | grep -q "^$SH_BLOB "; then sh_hit=1; fi
  # path-independent: any blob whose sha256 matches the dropper
  while read -r b p; do
    [ -z "$b" ] && continue
    [ "$($G cat-file -t "$b" 2>/dev/null)" = "blob" ] || continue
    sz=$($G cat-file -s "$b" 2>/dev/null)
    [ "$sz" = "$SH_SIZE" ] || continue
    h=$($G cat-file -p "$b" 2>/dev/null | shasum -a 256 | cut -d' ' -f1)
    [ "$h" = "$SH_SHA256" ] && { sh_hit=1; echo "$repo,$b,\"$p\",SHA256_MATCH_SHAI_HULUD_DROPPER" >> "$F_IOC"; }
  done < <(printf '%s\n' "$objs" | awk 'NF==2')

  # -- 2. January dropper + any folderOpen autorun, across ALL refs ----------
  jan_hit=0; autorefs=0
  for ref in $($G for-each-ref --format='%(refname)'); do
    while read -r mode type blob path; do
      [ -z "$blob" ] && continue
      case "$path" in
        .vscode/tasks.json|*/.vscode/tasks.json)
          c=$($G cat-file -p "$blob" 2>/dev/null)
          if printf '%s' "$c" | grep -q 'folderOpen'; then
            autorefs=$((autorefs+1))
            cmd=$(printf '%s' "$c" | grep -o '"command"[^,]*' | head -1 | tr -d '\n' | cut -c1-160)
            echo "$repo,$ref,$blob,\"$path\",\"$(printf '%s' "$cmd" | sed 's/"/""/g')\"" >> "$F_AUTO"
          fi
          [ "$blob" = "$JAN_BLOB" ] && jan_hit=1
          ;;
      esac
    done < <($G ls-tree -r "$ref" 2>/dev/null | grep -E '\.vscode/(tasks|settings|launch)\.json')
  done

  # -- 3. pipe-to-shell + IOC strings + npm hooks over EVERY blob -----------
  pipe_n=0; ioc_n=0; npm_n=0; wf_n=0
  while read -r b p; do
    [ -z "$b" ] && continue
    [ "$($G cat-file -t "$b" 2>/dev/null)" = "blob" ] || continue
    sz=$($G cat-file -s "$b" 2>/dev/null); [ "${sz:-0}" -gt 2000000 ] && continue
    c=$($G cat-file -p "$b" 2>/dev/null | head -c 200000)

    if printf '%s' "$c" | grep -qE "$IOC"; then
      m=$(printf '%s' "$c" | grep -oE "$IOC" | sort -u | head -3 | tr '\n' ' ')
      echo "$repo,$b,\"$p\",\"$m\"" >> "$F_IOC"; ioc_n=$((ioc_n+1))
    fi
    if printf '%s' "$c" | grep -qE "$PIPE"; then
      pipe_n=$((pipe_n+1))
      echo "$repo,$b,\"$p\",\"PIPE_TO_SHELL: $(printf '%s' "$c" | grep -oE "$PIPE" | head -1 | cut -c1-120 | sed 's/"/""/g')\"" >> "$F_IOC"
    fi
    case "$p" in
      package.json|*/package.json)
        for hook in preinstall postinstall install prepare prepublish; do
          v=$(printf '%s' "$c" | tr -d '\n' | grep -oE "\"$hook\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" | head -1)
          [ -n "$v" ] && { echo "$repo,$b,\"$p\",$hook,\"$(printf '%s' "$v" | cut -c1-150 | sed 's/"/""/g')\"" >> "$F_NPM"; npm_n=$((npm_n+1)); }
        done ;;
      .github/workflows/*)
        printf '%s' "$c" | grep -qE 'node +-e|curl[^|]*\||base64 +-d' && { echo "$repo,$b,\"$p\",\"suspicious-exec\"" >> "$F_WF"; wf_n=$((wf_n+1)); } ;;
    esac
  done < <(printf '%s\n' "$objs" | awk 'NF==2')

  # -- 4. commit forgery signature + contributors ---------------------------
  forged=0
  while IFS='|' read -r sha an ae ai cn ce ci sub par; do
    [ -z "$sha" ] && continue
    r=""
    az=$(printf '%s' "$ai" | grep -oE '[+-][0-9]{2}:[0-9]{2}$')
    cz=$(printf '%s' "$ci" | grep -oE '[+-][0-9]{2}:[0-9]{2}$')
    [ -n "$az" ] && [ -n "$cz" ] && [ "$az" != "$cz" ] && r="tz_mismatch($az/$cz)"
    [ "$an" != "$cn" ] && r="${r:+$r;}author_ne_committer"
    [ -z "$par" ] && r="${r:+$r;}orphan_commit"
    case "$ae" in *"$ACTOR_A"*) r="${r:+$r;}ACTOR_A_AUTHOR";; esac
    case "$ce" in *"$ACTOR_A"*) r="${r:+$r;}ACTOR_A_COMMITTER";; esac
    if [ -n "$r" ]; then
      forged=$((forged+1))
      echo "$repo,$sha,\"$an <$ae>\",$ai,\"$cn <$ce>\",$ci,\"$r\",\"$(printf '%s' "$sub" | cut -c1-90 | sed 's/"/""/g')\"" >> "$F_FORGE"
    fi
  done < <($G log --all --format='%H|%an|%ae|%aI|%cn|%ce|%cI|%s|%P' 2>/dev/null)

  $G log --all --format='%an|%ae' 2>/dev/null | sort | uniq -c | sort -rn | while read -r n line; do
    nm="${line%%|*}"; em="${line#*|}"
    fl="ok"
    case "$em" in
      *@goavanto.com|*@agenticdream.com|*users.noreply.github.com|*@avantodev.com) fl="corp" ;;
      *"$ACTOR_A"*) fl="!!ACTOR" ;;
      *) fl="EXTERNAL_EMAIL" ;;
    esac
    echo "$repo,\"$nm\",$em,$n,$fl" >> "$F_CONTRIB"
  done

  v="CLEAN"
  [ "$autorefs" -gt 0 ] && v="INFECTED_AUTORUN"
  [ "$jan_hit" = "1" ] && v="INFECTED_JAN_DROPPER"
  [ "$sh_hit" = "1" ] && v="INFECTED_SHAI_HULUD"
  echo "$repo,$nrefs,$ncommits,$sh_hit,$jan_hit,$autorefs,$pipe_n,$npm_n,$ioc_n,$wf_n,$forged,$v" >> "$F_SUM"
  log "    $v  refs=$nrefs commits=$ncommits autorun=$autorefs pipe=$pipe_n ioc=$ioc_n npm=$npm_n forged=$forged"
done < "$LIST"

log "DEEP SCAN COMPLETE -> $OUT"
