#!/usr/bin/env bash
# Scan funnel batches FROM..TO in order, logging to run.log. A failed batch does not stop the rest.
#   tools/run_batches.sh 3 15
set -u
cd "$(dirname "$0")/.."
export PATH="${FRAMEWORK_HUNTER_VENV:-$HOME/framework-hunter-work/.venv}/bin:$PATH"
stamp() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" >> run.log; }
for n in $(seq "$1" "$2"); do
    stamp "BATCH $n: starting"
    python3 -u tools/batch.py "$n" >> run.log 2>&1
    stamp "BATCH $n: finished with exit $?"
done
