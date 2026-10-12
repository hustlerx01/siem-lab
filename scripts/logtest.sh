#!/usr/bin/env bash
# Feed every sample file into wazuh-logtest inside the manager and save output.
# One wazuh-logtest process per file = one logtest session, so frequency/timeframe
# correlation rules (100110-100114) can fire across the events of that file.
# Override the exec prefix to use a plain container, e.g.
#   WAZUH_EXEC="docker exec -i siemlab-mgr" ./scripts/logtest.sh
set -euo pipefail
cd "$(dirname "$0")/.."
EXEC=${WAZUH_EXEC:-docker compose exec -T wazuh.manager}
out=results/wazuh_logtest.txt; : > "$out"
for f in samples/*/*.jsonl; do
  echo "##### FILE $f ($(wc -l < "$f") events)" >> "$out"
  $EXEC /var/ossec/bin/wazuh-logtest < "$f" >> "$out" 2>&1 || true
done
grep -E "^##### FILE|id: '1001|Alert to be generated" "$out"
