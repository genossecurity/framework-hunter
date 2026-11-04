#!/bin/sh
rm -f /work/CANARY_PWNED
node /work/poc.mjs
echo "----"
if [ -f /work/CANARY_PWNED ]; then
  echo "RESULT: INJECTION CONFIRMED — \$() in the Auditor's issue title executed a shell command (canary created)."
else
  echo "RESULT: no injection (canary absent)."
fi
